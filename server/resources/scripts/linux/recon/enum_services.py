SCRIPT_METADATA = {
    "name": "linux/recon/listening_services",
    "display_name": "Enumerate Listening Services",
    "description": "Discover all listening TCP/UDP ports, identify associated processes, and detect web services with HTTP probing",
    "platforms": ["linux"],
    "category": "Recon",
    "params": [
        {
            "name": "mode",
            "type": "select",
            "required": False,
            "default": "service",
            "options": ["service", "web"],
            "description": "service: basic port/process info; web: also HTTP probe for titles and headers"
        }
    ]
}

import os
import re
import ssl
import sys
import json
import pwd
import html
import socket
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen


NOISE_COMM = {
    "systemd", "systemd-resolved", "systemd-timesyncd", "dbus-daemon",
    "avahi-daemon", "rsyslogd", "cron", "crond", "agetty", "polkitd",
    "NetworkManager", "wpa_supplicant", "udisksd", "upowerd", "ModemManager"
}

SYSTEMD_NOISE_UNITS = {
    "systemd-resolved.service",
    "systemd-timesyncd.service",
    "dbus.service",
    "dbus-broker.service",
    "avahi-daemon.service",
    "rsyslog.service",
    "cron.service",
    "crond.service",
    "getty@tty1.service",
    "systemd-logind.service",
    "NetworkManager.service",
    "wpa_supplicant.service",
}

PROJECT_MARKERS = [
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "manage.py",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "Cargo.toml",
    "go.mod",
]


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def readlink_safe(path):
    try:
        return os.readlink(str(path))
    except Exception:
        return None


def run(cmd, timeout=5):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout
        )
        return p.returncode == 0, p.stdout.strip()
    except Exception:
        return False, ""


def list_pids():
    out = []
    for p in Path("/proc").iterdir():
        if p.name.isdigit():
            out.append(int(p.name))
    return out


def get_proc_meta(pid):
    proc = Path(f"/proc/{pid}")
    if not proc.exists():
        return None

    exe = readlink_safe(proc / "exe")
    cwd = readlink_safe(proc / "cwd")
    comm = read_text(proc / "comm").strip() or None
    cmdline_raw = read_text(proc / "cmdline")
    argv = [x for x in cmdline_raw.split("\x00") if x]
    cmdline = " ".join(argv) if argv else None

    user = None
    try:
        user = pwd.getpwuid(proc.stat().st_uid).pw_name
    except Exception:
        pass

    ppid = None
    status = read_text(proc / "status")
    m = re.search(r"^PPid:\s+(\d+)", status, re.M)
    if m:
        ppid = int(m.group(1))

    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "exe": exe,
        "exe_name": Path(exe).name if exe else comm,
        "cwd": cwd,
        "argv": argv,
        "cmdline": cmdline,
        "user": user,
    }


def split_addr_port(addr):
    addr = addr.strip()
    if addr.startswith("[") and "]:" in addr:
        i = addr.rfind("]:")
        return addr[1:i], int(addr[i + 2:])
    if addr.count(":") >= 2:
        i = addr.rfind(":")
        try:
            return addr[:i], int(addr[i + 1:])
        except Exception:
            return addr, None
    if ":" in addr:
        i = addr.rfind(":")
        try:
            return addr[:i], int(addr[i + 1:])
        except Exception:
            return addr, None
    return addr, None


def is_loopback(host):
    return host in ("127.0.0.1", "::1", "localhost")


def build_inode_map():
    inode_map = {}
    proc_cache = {}

    for pid in list_pids():
        meta = get_proc_meta(pid)
        if not meta:
            continue
        proc_cache[pid] = meta

        fd_dir = Path(f"/proc/{pid}/fd")
        if not fd_dir.exists():
            continue

        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd))
                except Exception:
                    continue
                m = re.match(r"socket:\[(\d+)\]", target)
                if m:
                    inode_map[m.group(1)] = meta
        except Exception:
            pass

    return inode_map, proc_cache


def parse_ss_listeners():
    rows = []
    ok, out = run(["ss", "-lntupH"])
    if not ok or not out:
        return rows

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        local = parts[4]
        process_part = " ".join(parts[6:]) if len(parts) >= 7 else ""

        host, port = split_addr_port(local)
        if port is None:
            continue

        pid = None
        inode = None

        m = re.search(r"pid=(\d+)", process_part)
        if m:
            pid = int(m.group(1))

        m = re.search(r"ino:(\d+)", process_part)
        if m:
            inode = m.group(1)

        rows.append({
            "proto": proto,
            "listen_host": host,
            "port": port,
            "pid": pid,
            "inode": inode,
        })

    return rows


def get_systemd_unit(pid):
    if not pid:
        return None

    cgroup = read_text(f"/proc/{pid}/cgroup")
    if not cgroup:
        return None

    for line in cgroup.splitlines():
        m = re.search(r"/([^/\n]+\.service)\b", line)
        if m:
            return m.group(1)
        m = re.search(r"/([^/\n]+\.socket)\b", line)
        if m:
            return m.group(1)

    return None


def resolve_existing_path(value):
    if not value:
        return None
    try:
        p = Path(value)
        if p.exists():
            return p.resolve()
    except Exception:
        pass
    return None


def is_probable_runtime_path(path):
    if not path:
        return False
    s = str(path)
    bad_prefixes = (
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt",
        "/snap", "/nix", "/var/lib", "/run", "/proc", "/sys", "/dev"
    )
    return not s.startswith(bad_prefixes)


def iter_parent_dirs(path, max_depth=6):
    if not path:
        return
    cur = path
    seen = set()
    depth = 0
    while cur and depth <= max_depth:
        key = str(cur)
        if key in seen:
            break
        seen.add(key)
        yield cur
        if cur.parent == cur:
            break
        cur = cur.parent
        depth += 1


def detect_script_entry(meta):
    argv = meta.get("argv") or []
    exe_name = (meta.get("exe_name") or "").lower()

    if not argv:
        return None

    for i in range(1, len(argv)):
        a = argv[i]
        if not a or a.startswith("-"):
            continue

        p = resolve_existing_path(a)
        if p and p.is_file():
            return p

        if exe_name.startswith("python") and a.endswith(".py"):
            p = resolve_existing_path(a)
            if p:
                return p

        if exe_name in {"node", "nodejs", "bun"} and a.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
            p = resolve_existing_path(a)
            if p:
                return p

        if exe_name == "php" and a.endswith(".php"):
            p = resolve_existing_path(a)
            if p:
                return p

        if exe_name == "ruby" and a.endswith(".rb"):
            p = resolve_existing_path(a)
            if p:
                return p

    return None


def looks_like_app_root(path):
    for fname in PROJECT_MARKERS:
        if (path / fname).exists():
            return True

    if (path / "Dockerfile").exists():
        return True

    if (path / ".git").exists():
        return True

    return False


def detect_app(meta):
    candidates = []

    script_entry = detect_script_entry(meta)
    cwd = resolve_existing_path(meta.get("cwd"))
    exe = resolve_existing_path(meta.get("exe"))

    if script_entry:
        candidates.append(("script_dir", script_entry.parent, script_entry))
    if cwd and cwd.is_dir():
        candidates.append(("cwd", cwd, None))
    if exe:
        if exe.is_file():
            candidates.append(("exe_dir", exe.parent, exe))
        elif exe.is_dir():
            candidates.append(("exe_dir", exe, exe))

    seen = set()

    for source, base_dir, entry in candidates:
        for d in iter_parent_dirs(base_dir, max_depth=6):
            try:
                key = str(d.resolve()) if d.exists() else str(d)
            except Exception:
                key = str(d)

            if key in seen:
                continue
            seen.add(key)

            if looks_like_app_root(d):
                return {
                    "app_path": str(d),
                    "app_path_source": source,
                    "entry_file": str(entry) if entry else None,
                }

    if script_entry:
        return {
            "app_path": str(script_entry.parent),
            "app_path_source": "script_dir",
            "entry_file": str(script_entry),
        }

    if cwd and cwd.is_dir() and is_probable_runtime_path(cwd):
        return {
            "app_path": str(cwd),
            "app_path_source": "cwd",
            "entry_file": None,
        }

    return {
        "app_path": None,
        "app_path_source": None,
        "entry_file": None,
    }


def normalize_unit_name(unit):
    if not unit:
        return None
    return unit.replace(".service", "").replace(".socket", "")


def choose_name(systemd_unit, app_path):
    if systemd_unit and systemd_unit not in SYSTEMD_NOISE_UNITS:
        return normalize_unit_name(systemd_unit), "systemd_unit"

    if app_path:
        base = Path(app_path).name
        if base and base not in {"", "/", "current"}:
            return base, "app_path_basename"

    return None, None


def is_noise(meta, systemd_unit):
    if meta.get("comm") in NOISE_COMM:
        return True
    if systemd_unit in SYSTEMD_NOISE_UNITS:
        return True
    return False


def extract_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return None
    title = html.unescape(m.group(1))
    title = re.sub(r"\s+", " ", title).strip()
    return title or None


def http_probe_once(url, insecure=False, timeout=3):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
    ctx = ssl._create_unverified_context() if insecure else None

    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read(65536).decode("utf-8", errors="ignore")
            return {
                "ok": True,
                "url": url,
                "status": getattr(r, "status", None),
                "server": r.headers.get("Server"),
                "content_type": r.headers.get("Content-Type"),
                "title": extract_title(data),
                "final_url": r.geturl(),
            }
    except Exception as e:
        return {
            "ok": False,
            "url": url,
            "error": str(e),
        }


def detect_http_any(port, listen_host):
    hosts = ["127.0.0.1"]

    if listen_host and listen_host not in ("*", "0.0.0.0", "::", "[::]") and not is_loopback(listen_host):
        hosts.append(listen_host)

    tried = set()

    for host in hosts:
        for scheme in ("http", "https"):
            key = (host, scheme, port)
            if key in tried:
                continue
            tried.add(key)

            url = f"{scheme}://{host}:{port}/"
            res = http_probe_once(url, insecure=(scheme == "https"))
            if res["ok"]:
                res["scheme"] = scheme
                res["probe_host"] = host
                return res

    return None


def merge_listeners():
    ss_rows = parse_ss_listeners()
    inode_map, proc_cache = build_inode_map()
    merged = []

    for row in ss_rows:
        meta = None

        if row["pid"] and row["pid"] in proc_cache:
            meta = proc_cache[row["pid"]]
        elif row["pid"]:
            meta = get_proc_meta(row["pid"])
        elif row["inode"] and row["inode"] in inode_map:
            meta = inode_map[row["inode"]]

        if not meta:
            meta = {
                "pid": row["pid"],
                "ppid": None,
                "comm": None,
                "exe": None,
                "exe_name": None,
                "cwd": None,
                "argv": [],
                "cmdline": None,
                "user": None,
            }

        systemd_unit = get_systemd_unit(meta.get("pid"))
        app = detect_app(meta)
        name, name_source = choose_name(systemd_unit, app.get("app_path"))

        merged.append({
            "proto": row["proto"],
            "host": row["listen_host"],
            "port": row["port"],
            "pid": meta.get("pid"),
            "user": meta.get("user"),
            "comm": meta.get("comm"),
            "exe": meta.get("exe"),
            "process": meta.get("exe_name") or meta.get("comm"),
            "cmdline": meta.get("cmdline"),
            "unit": systemd_unit,
            "app_path": app.get("app_path"),
            "name": name,
            "name_source": name_source,
        })

    return merged


def is_useful_listener(item):
    if is_noise({"comm": item.get("comm")}, item.get("unit")):
        return False

    proto = item["proto"]
    host = item["host"]

    if proto.startswith("udp"):
        return True

    if is_loopback(host):
        if item.get("unit") and item["unit"] not in SYSTEMD_NOISE_UNITS:
            return True
        if item.get("app_path"):
            return True
        if item.get("cmdline"):
            return True
        return False

    return True


def build_service_ports(items):
    out = []
    seen = set()

    for item in items:
        if not is_useful_listener(item):
            continue

        row = {
            "port": item["port"],
            "proto": item["proto"],
            "host": item["host"],
            "pid": item["pid"],
            "user": item["user"],
            "process": item["process"],
            "exe": item["exe"],
            "cmdline": item["cmdline"],
            "unit": item["unit"],
            "app_path": item["app_path"],
            "name": item["name"],
            "name_source": item["name_source"],
        }

        k = (row["proto"], row["host"], row["port"], row["pid"])
        if k in seen:
            continue
        seen.add(k)
        out.append(row)

    out.sort(key=lambda x: (x["port"], x["pid"] or 0))
    return out


def build_web_services(items):
    out = []
    seen = set()

    for item in items:
        if not item["proto"].startswith("tcp"):
            continue
        if is_noise({"comm": item.get("comm")}, item.get("unit")):
            continue

        probe = detect_http_any(item["port"], item["host"])
        if not probe:
            continue

        row = {
            "port": item["port"],
            "host": item["host"],
            "pid": item["pid"],
            "user": item["user"],
            "process": item["process"],
            "exe": item["exe"],
            "cmdline": item["cmdline"],
            "unit": item["unit"],
            "app_path": item["app_path"],
            "name": item["name"],
            "name_source": item["name_source"],
            "scheme": probe["scheme"],
            "status": probe["status"],
            "server": probe["server"],
            "content_type": probe["content_type"],
            "title": probe["title"],
            "url": probe["final_url"],
            "probe_host": probe["probe_host"],
        }

        k = (row["port"], row["pid"], row["scheme"])
        if k in seen:
            continue
        seen.add(k)
        out.append(row)

    out.sort(key=lambda x: (x["port"], x["pid"] or 0))
    return out


listeners = merge_listeners()

try:
    mode = kwargs.get("mode", "service")
except NameError:
    mode = "service"

builders = {
    "service": build_service_ports,
    "web": build_web_services,
}

if mode not in builders:
    raise ValueError(f"invalid mode: {mode}, expected 'service' or 'web'")

print(json.dumps(builders[mode](listeners), ensure_ascii=False, indent=2))