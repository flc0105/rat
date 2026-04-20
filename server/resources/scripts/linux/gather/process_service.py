#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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


TARGET_RUNTIME = "python"


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


def extract_script_name(argv):
    if not argv:
        return None

    for arg in argv[1:]:
        if not arg.startswith("-"):
            name = Path(arg).name
            if name not in ("node", "npm", "npx"):
                return name

    return None


def detect_project_name(cwd, exe, argv):
    candidates = []

    if cwd:
        candidates.append(Path(cwd))

    if exe:
        try:
            candidates.append(Path(exe).resolve().parent)
        except Exception:
            candidates.append(Path(exe).parent)

    for arg in argv[1:]:
        if not arg.startswith("-") and "/" in arg:
            try:
                candidates.append(Path(arg).resolve().parent)
            except Exception:
                candidates.append(Path(arg).parent)

    seen = set()

    for base in candidates:
        if not base:
            continue
        try:
            base = base.resolve()
        except Exception:
            pass

        if str(base) in seen:
            continue
        seen.add(str(base))

        for p in [base, base.parent]:
            if not p or p == p.parent.parent:
                pass

            pkg = p / "package.json"
            if pkg.exists():
                txt = read_text(pkg)
                m = re.search(r'"name"\s*:\s*"([^"]+)"', txt)
                if m:
                    return m.group(1), "package.json:name"

    return None, None


def build_service_name(meta):
    unit = meta.get("systemd_unit")
    if unit:
        return unit.replace(".service", "").replace(".socket", ""), "systemd_unit"

    script_name = extract_script_name(meta.get("argv") or [])
    if script_name:
        return Path(script_name).stem, "script_name"

    project_name, project_src = detect_project_name(
        meta.get("cwd"),
        meta.get("exe"),
        meta.get("argv") or [],
    )
    if project_name:
        return project_name, project_src

    exe_name = meta.get("exe_name")
    if exe_name:
        return exe_name, "exe_name"

    return meta.get("comm"), "comm"


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

        meta["systemd_unit"] = get_systemd_unit(pid)
        service_name, service_name_source = build_service_name(meta)
        meta["service_name"] = service_name
        meta["service_name_source"] = service_name_source
        out.append(meta)

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
                "listen_host": host,
                "port": port,
                "pid": pid,
                "raw_process": proc_text,
            }
        )

    return rows


def infer_banner(host, port, timeout=2):
    result = {
        "protocol_hint": None,
        "banner": None,
    }

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
                result["protocol_hint"] = "ssh"
            elif text.startswith("220 "):
                result["protocol_hint"] = "ftp"

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
            raw = r.read(65536)
            body = raw.decode("utf-8", errors="ignore")
            return {
                "ok": True,
                "status": getattr(r, "status", None),
                "server_header": r.headers.get("Server"),
                "content_type": r.headers.get("Content-Type"),
                "title": extract_title(body),
                "final_url": r.geturl(),
            }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
        }


def detect_http(host, port):
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}:{port}/"
        res = http_probe_once(url, insecure=(scheme == "https"))
        if res["ok"]:
            res["http_type"] = scheme
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
    http_services = []
    seen_ports = set()

    for item in sorted(port_rows, key=lambda x: (x["port"], x["proto"], x["listen_host"])):
        key = (item["proto"], item["listen_host"], item["port"])
        if key in seen_ports:
            continue
        seen_ports.add(key)

        banner = None
        protocol_hint = None

        if item["proto"].startswith("tcp"):
            b = infer_banner("127.0.0.1", item["port"])
            banner = b["banner"]
            protocol_hint = b["protocol_hint"]

        ports.append(
            {
                "port": item["port"],
                "proto": item["proto"],
                "listen_host": item["listen_host"],
                "protocol_hint": protocol_hint,
                "banner": banner,
            }
        )

        if item["proto"].startswith("tcp"):
            web = detect_http("127.0.0.1", item["port"])
            if web:
                http_services.append(
                    {
                        "port": item["port"],
                        "listen_host": item["listen_host"],
                        "http_type": web["http_type"],
                        "status": web["status"],
                        "server_header": web["server_header"],
                        "content_type": web["content_type"],
                        "title": web["title"],
                        "final_url": web["final_url"],
                    }
                )

    result.append(
        {
            "runtime_type": TARGET_RUNTIME,
            "pid": pid,
            "user": proc["user"],
            "service_name": proc["service_name"],
            "service_name_source": proc["service_name_source"],
            "process_name": proc["exe_name"] or proc["comm"],
            "exe": proc["exe"],
            "cwd": proc["cwd"],
            "cmdline": proc["cmdline"],
            "argv": proc["argv"],
            "systemd_unit": proc["systemd_unit"],
            "ports": ports,
            "http_services": http_services,
        }
    )

print(json.dumps(result, ensure_ascii=False, indent=2))