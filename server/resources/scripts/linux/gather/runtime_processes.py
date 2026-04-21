SCRIPT_METADATA = {
    "name": "linux/recon/runtime_processes",
    "display_name": "Discover Runtime Processes",
    "description": "Find all processes of a specific runtime (python, node, java) and enumerate their listening ports and web services",
    "platforms": ["linux"],
    "category": "Recon",
    "params": [
        {
            "name": "runtime",
            "type": "select",
            "required": False,
            "default": "python",
            "options": ["python", "node", "java"],
            "description": "Target runtime to search for"
        }
    ]
}

import os
import re
import ssl
import json
import html
import pwd
import socket
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen


TARGET_RUNTIME = kwargs.get("runtime", "python")


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


def split_addr_port(addr):
    addr = addr.strip()

    if addr.startswith("[") and "]:" in addr:
        i = addr.rfind("]:")
        return addr[1:i], int(addr[i + 2:])

    i = addr.rfind(":")
    if i == -1:
        return addr, None

    host = addr[:i]
    port = addr[i + 1:]
    try:
        return host, int(port)
    except Exception:
        return host, None


def is_loopback(host):
    return host in ("127.0.0.1", "::1", "localhost")


def run(cmd, timeout=5):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout,
    )
    if p.returncode != 0:
        return False, p.stderr.strip()
    return True, p.stdout


def get_user_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return None


def get_systemd_unit(pid):
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


def normalize_unit_name(unit):
    if not unit:
        return None
    return unit.replace(".service", "").replace(".socket", "")


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


def detect_app_path(meta):
    candidates = []

    script_entry = detect_script_entry(meta)
    cwd = resolve_existing_path(meta.get("cwd"))
    exe = resolve_existing_path(meta.get("exe"))

    if script_entry:
        candidates.append(script_entry.parent)
    if cwd and cwd.is_dir():
        candidates.append(cwd)
    if exe:
        if exe.is_file():
            candidates.append(exe.parent)
        elif exe.is_dir():
            candidates.append(exe)

    seen = set()

    for base_dir in candidates:
        for d in iter_parent_dirs(base_dir, max_depth=6):
            try:
                key = str(d.resolve()) if d.exists() else str(d)
            except Exception:
                key = str(d)

            if key in seen:
                continue
            seen.add(key)

            if looks_like_app_root(d):
                return str(d)

    if script_entry:
        return str(script_entry.parent)

    if cwd and cwd.is_dir() and is_probable_runtime_path(cwd):
        return str(cwd)

    return None


def choose_name(unit, app_path):
    if unit:
        return normalize_unit_name(unit), "systemd_unit"

    if app_path:
        base = Path(app_path).name
        if base and base not in {"", "/", "current"}:
            return base, "app_path_basename"

    return None, None


def is_target_process(meta):
    text_parts = [
        meta.get("comm") or "",
        meta.get("exe_name") or "",
        meta.get("exe") or "",
        meta.get("cmdline") or "",
    ]
    text = " ".join(text_parts).lower()

    if TARGET_RUNTIME == "python":
        return "python" in text

    if TARGET_RUNTIME == "node":
        argv = meta.get("argv") or []
        arg0 = Path(argv[0]).name.lower() if argv else ""

        if "node" in text:
            return True
        if arg0 in ("node", "nodejs", "npm", "npx"):
            return True
        if " npm " in f" {text} " or " npx " in f" {text} ":
            return True
        return False

    if TARGET_RUNTIME == "java":
        argv = meta.get("argv") or []
        arg0 = Path(argv[0]).name.lower() if argv else ""
        if "java" in text or arg0 == "java":
            return True
        return False

    return False


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

    try:
        st = proc.stat()
        user = get_user_name(st.st_uid)
    except Exception:
        user = None

    return {
        "pid": pid,
        "comm": comm,
        "exe": exe,
        "exe_name": Path(exe).name if exe else comm,
        "cwd": cwd,
        "argv": argv,
        "cmdline": cmdline,
        "user": user,
    }


def list_target_processes():
    out = []

    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue

        pid = int(p.name)
        meta = get_proc_meta(pid)
        if not meta:
            continue

        if not is_target_process(meta):
            continue

        unit = get_systemd_unit(pid)
        app_path = detect_app_path(meta)
        name, name_source = choose_name(unit, app_path)

        out.append(
            {
                "runtime": TARGET_RUNTIME,
                "pid": pid,
                "user": meta["user"],
                "name": name,
                "name_source": name_source,
                "process": meta["exe_name"] or meta["comm"],
                "exe": meta["exe"],
                "cmdline": meta["cmdline"],
                "unit": unit,
                "app_path": app_path,
            }
        )

    out.sort(key=lambda x: x["pid"])
    return out


def parse_ss_listeners():
    ok, out = run(["ss", "-lntupH"])
    if not ok:
        raise RuntimeError(out or "ss -lntupH failed")

    rows = []

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0].lower()
        local_addr = parts[4]
        proc_text = " ".join(parts[6:]) if len(parts) >= 7 else ""

        host, port = split_addr_port(local_addr)
        if port is None:
            continue

        pid = None
        m = re.search(r"pid=(\d+)", proc_text)
        if m:
            pid = int(m.group(1))

        rows.append(
            {
                "proto": proto,
                "host": host,
                "port": port,
                "pid": pid,
            }
        )

    return rows


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
            raw = r.read(65536)
            body = raw.decode("utf-8", errors="ignore")
            return {
                "ok": True,
                "status": getattr(r, "status", None),
                "server": r.headers.get("Server"),
                "content_type": r.headers.get("Content-Type"),
                "title": extract_title(body),
                "url": r.geturl(),
            }
    except Exception:
        return {
            "ok": False,
        }


def detect_http(host, port):
    hosts = ["127.0.0.1"]

    if host and host not in ("*", "0.0.0.0", "::", "[::]") and not is_loopback(host):
        hosts.append(host)

    tried = set()

    for probe_host in hosts:
        for scheme in ("http", "https"):
            key = (probe_host, scheme, port)
            if key in tried:
                continue
            tried.add(key)

            url = f"{scheme}://{probe_host}:{port}/"
            res = http_probe_once(url, insecure=(scheme == "https"))
            if res["ok"]:
                res["scheme"] = scheme
                res["probe_host"] = probe_host
                return res

    return None


processes = list_target_processes()
listeners = parse_ss_listeners()

pid_to_ports = {}
for row in listeners:
    pid = row.get("pid")
    if not pid:
        continue
    pid_to_ports.setdefault(pid, []).append(row)

result = []

for proc in processes:
    pid = proc["pid"]
    port_rows = pid_to_ports.get(pid, [])

    ports = []
    web = []
    seen_ports = set()

    for item in sorted(port_rows, key=lambda x: (x["port"], x["proto"], x["host"])):
        key = (item["proto"], item["host"], item["port"])
        if key in seen_ports:
            continue
        seen_ports.add(key)

        ports.append(
            {
                "port": item["port"],
                "proto": item["proto"],
                "host": item["host"],
            }
        )

        if item["proto"].startswith("tcp"):
            web_res = detect_http(item["host"], item["port"])
            if web_res:
                web.append(
                    {
                        "port": item["port"],
                        "host": item["host"],
                        "scheme": web_res["scheme"],
                        "status": web_res["status"],
                        "server": web_res["server"],
                        "content_type": web_res["content_type"],
                        "title": web_res["title"],
                        "url": web_res["url"],
                        "probe_host": web_res["probe_host"],
                    }
                )

    result.append(
        {
            "runtime": proc["runtime"],
            "pid": proc["pid"],
            "user": proc["user"],
            "name": proc["name"],
            "name_source": proc["name_source"],
            "process": proc["process"],
            "exe": proc["exe"],
            "cmdline": proc["cmdline"],
            "unit": proc["unit"],
            "app_path": proc["app_path"],
            "ports": ports,
            "web": web,
        }
    )

print(json.dumps(result, ensure_ascii=False, indent=2))