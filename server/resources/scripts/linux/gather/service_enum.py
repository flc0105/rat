#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import ssl
import sys
import json
import time
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

PROJECT_FILES = [
    ("package.json", "node"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("manage.py", "django"),
    ("pom.xml", "java-maven"),
    ("build.gradle", "java-gradle"),
    ("composer.json", "php"),
    ("Gemfile", "ruby"),
    ("Cargo.toml", "rust"),
    ("go.mod", "go"),
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


def get_container_identity(pid):
    info = {
        "container_type": None,
        "container_id": None,
        "k8s_pod": None,
    }
    if not pid:
        return info

    cgroup = read_text(f"/proc/{pid}/cgroup")
    if not cgroup:
        return info

    for line in cgroup.splitlines():
        if "docker" in line:
            m = re.search(r"([0-9a-f]{12,64})", line)
            if m:
                info["container_type"] = "docker"
                info["container_id"] = m.group(1)
                break
        if "kubepods" in line:
            info["container_type"] = "kubernetes"
            m = re.search(r"pod([a-f0-9_-]{8,})", line)
            if m:
                info["k8s_pod"] = m.group(1)
            m = re.search(r"([0-9a-f]{12,64})", line)
            if m:
                info["container_id"] = m.group(1)
    return info


def parse_project_name_from_file(base):
    try:
        p = Path(base)

        f = p / "package.json"
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'"name"\s*:\s*"([^"]+)"', txt)
            if m:
                return m.group(1), "package.json:name"

        f = p / "pyproject.toml"
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', txt, re.M)
            if m:
                return m.group(1), "pyproject.toml:name"

        f = p / "composer.json"
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'"name"\s*:\s*"([^"]+)"', txt)
            if m:
                return m.group(1), "composer.json:name"

        f = p / "pom.xml"
        if f.exists():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"<artifactId>([^<]+)</artifactId>", txt)
            if m:
                return m.group(1).strip(), "pom.xml:artifactId"
    except Exception:
        pass

    return None, None


def detect_project(meta):
    cwd = meta.get("cwd")
    exe = meta.get("exe")
    candidates = []

    if cwd:
        candidates.append(Path(cwd))
    if exe:
        try:
            candidates.append(Path(exe).resolve().parent)
        except Exception:
            candidates.append(Path(exe).parent)

    seen = set()

    for base in candidates:
        try:
            base = base.resolve()
        except Exception:
            pass

        key = str(base)
        if key in seen:
            continue
        seen.add(key)

        for fname, ptype in PROJECT_FILES:
            if (base / fname).exists():
                name, src = parse_project_name_from_file(base)
                return {
                    "project_path": str(base),
                    "project_type": ptype,
                    "project_name": name,
                    "project_name_source": src,
                }

        parent = base.parent if base.parent != base else None
        if parent:
            for fname, ptype in PROJECT_FILES:
                if (parent / fname).exists():
                    name, src = parse_project_name_from_file(parent)
                    return {
                        "project_path": str(parent),
                        "project_type": ptype,
                        "project_name": name,
                        "project_name_source": src,
                    }

    return {
        "project_path": cwd,
        "project_type": None,
        "project_name": None,
        "project_name_source": None,
    }


def service_name_from_evidence(meta, systemd_unit, project):
    if systemd_unit and systemd_unit not in SYSTEMD_NOISE_UNITS:
        return systemd_unit.replace(".service", "").replace(".socket", ""), "systemd_unit"

    if project.get("project_name"):
        return project["project_name"], project["project_name_source"]

    argv = meta.get("argv") or []
    if argv:
        arg0 = Path(argv[0]).name
        if arg0 and arg0 not in NOISE_COMM:
            return arg0, "argv0"

    exe_name = meta.get("exe_name")
    if exe_name and exe_name not in NOISE_COMM:
        return exe_name, "exe_name"

    return None, None


def is_noise(meta, systemd_unit):
    if meta.get("comm") in NOISE_COMM:
        return True
    if systemd_unit in SYSTEMD_NOISE_UNITS:
        return True
    return False


def infer_banner(port, host="127.0.0.1", timeout=2):
    result = {"protocol": None, "banner": None}

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
            except Exception:
                data = b""

            if not data:
                return result

            text = data.decode("utf-8", errors="ignore").strip()
            result["banner"] = text or None

            if text.startswith("SSH-"):
                result["protocol"] = "ssh"
            elif text.startswith("220 "):
                result["protocol"] = "ftp"

            return result
    except Exception:
        return result


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

    for h in hosts:
        for scheme in ("http", "https"):
            key = (h, scheme, port)
            if key in tried:
                continue
            tried.add(key)

            url = f"{scheme}://{h}:{port}/"
            res = http_probe_once(url, insecure=(scheme == "https"))
            if res["ok"]:
                res["scheme"] = scheme
                res["probe_host"] = h
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
        container = get_container_identity(meta.get("pid"))
        project = detect_project(meta)
        service_name, service_name_source = service_name_from_evidence(meta, systemd_unit, project)

        merged.append({
            "proto": row["proto"],
            "listen_host": row["listen_host"],
            "port": row["port"],
            "pid": meta.get("pid"),
            "user": meta.get("user"),
            "comm": meta.get("comm"),
            "exe": meta.get("exe"),
            "exe_name": meta.get("exe_name"),
            "cwd": meta.get("cwd"),
            "argv": meta.get("argv"),
            "cmdline": meta.get("cmdline"),
            "systemd_unit": systemd_unit,
            "container": container,
            "project_path": project.get("project_path"),
            "project_type": project.get("project_type"),
            "project_name": project.get("project_name"),
            "project_name_source": project.get("project_name_source"),
            "service_name": service_name,
            "service_name_source": service_name_source,
        })

    return merged


def is_useful_listener(item):
    if is_noise(item, item.get("systemd_unit")):
        return False

    proto = item["proto"]
    host = item["listen_host"]

    if proto.startswith("udp"):
        return True

    if is_loopback(host):
        if item.get("systemd_unit") and item["systemd_unit"] not in SYSTEMD_NOISE_UNITS:
            return True
        if item.get("project_path"):
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

        banner = None
        protocol = None

        if item["proto"].startswith("tcp"):
            b = infer_banner(item["port"])
            banner = b["banner"]
            protocol = b["protocol"]

        row = {
            "port": item["port"],
            "proto": item["proto"],
            "listen_host": item["listen_host"],
            "pid": item["pid"],
            "user": item["user"],
            "process_name": item["exe_name"] or item["comm"],
            "exe": item["exe"],
            "cmdline": item["cmdline"],
            "systemd_unit": item["systemd_unit"],
            "container_type": item["container"]["container_type"],
            "container_id": item["container"]["container_id"],
            "k8s_pod": item["container"]["k8s_pod"],
            "project_name": item["project_name"],
            "project_name_source": item["project_name_source"],
            "project_path": item["project_path"],
            "project_type": item["project_type"],
            "service_name": item["service_name"],
            "service_name_source": item["service_name_source"],
            "protocol": protocol,
            "banner": banner,
        }

        k = (row["proto"], row["listen_host"], row["port"], row["pid"])
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
        if is_noise(item, item.get("systemd_unit")):
            continue

        probe = detect_http_any(item["port"], item["listen_host"])
        if not probe:
            continue

        row = {
            "port": item["port"],
            "listen_host": item["listen_host"],
            "pid": item["pid"],
            "user": item["user"],
            "process_name": item["exe_name"] or item["comm"],
            "exe": item["exe"],
            "cmdline": item["cmdline"],
            "systemd_unit": item["systemd_unit"],
            "container_type": item["container"]["container_type"],
            "container_id": item["container"]["container_id"],
            "k8s_pod": item["container"]["k8s_pod"],
            "project_name": item["project_name"],
            "project_name_source": item["project_name_source"],
            "project_path": item["project_path"],
            "project_type": item["project_type"],
            "service_name": item["service_name"],
            "service_name_source": item["service_name_source"],
            "http_type": probe["scheme"],
            "status": probe["status"],
            "server_header": probe["server"],
            "content_type": probe["content_type"],
            "title": probe["title"],
            "final_url": probe["final_url"],
            "probe_host": probe["probe_host"],
            "launcher": item["exe"],
            "launcher_args": item["argv"][1:] if item["argv"] else [],
        }

        k = (row["port"], row["pid"], row["http_type"])
        if k in seen:
            continue
        seen.add(k)
        out.append(row)

    out.sort(key=lambda x: (x["port"], x["pid"] or 0))
    return out


listeners = merge_listeners()

result = {
    "service_ports": build_service_ports(listeners),
    "web_services": build_web_services(listeners),
    "meta": {
        "generated_at": int(time.time()),
        "hostname": socket.gethostname(),
        "python": sys.executable,
    }
}

print(json.dumps(result, ensure_ascii=False, indent=2))