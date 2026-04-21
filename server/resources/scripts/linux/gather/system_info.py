SCRIPT_METADATA = {
    "name": "linux/recon/system_info",
    "display_name": "System Information",
    "description": "Collect comprehensive system information including OS, kernel, CPU, memory, GPU, network, and environment details",
    "platforms": ["linux"],
    "category": "Recon",
    "params": []
}

import os
import sys
import json
import socket
import shutil
import getpass
import platform
import subprocess
from pathlib import Path


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return ""


def run(cmd, timeout=3):
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


def gib_from_kib(v):
    try:
        return round(int(v) / 1024 / 1024, 2)
    except Exception:
        return None


def get_os():
    data = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return {
        "distro": data.get("NAME"),
        "version": data.get("VERSION") or data.get("VERSION_ID"),
        "pretty_name": data.get("PRETTY_NAME"),
    }


def get_kernel():
    return {
        "kernel": platform.release(),
        "arch": platform.machine(),
    }


def bad_dmi(v):
    if not v:
        return True
    x = v.strip().lower()
    return x in {
        "", "none", "null", "o.e.m.", "to be filled by o.e.m.",
        "to be filled by oem", "default string", "system product name",
        "system version", "not specified", "not applicable"
    }


def uniq_join(*parts):
    out = []
    seen = set()
    for p in parts:
        p = (p or "").strip()
        if not p:
            continue
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return " ".join(out) if out else None


def get_host():
    sys_vendor = read_text("/sys/class/dmi/id/sys_vendor")
    product_name = read_text("/sys/class/dmi/id/product_name")
    product_version = read_text("/sys/class/dmi/id/product_version")
    board_vendor = read_text("/sys/class/dmi/id/board_vendor")
    board_name = read_text("/sys/class/dmi/id/board_name")

    product = uniq_join(
        None if bad_dmi(sys_vendor) else sys_vendor,
        None if bad_dmi(product_name) else product_name,
        None if bad_dmi(product_version) else product_version,
    )
    board = uniq_join(
        None if bad_dmi(board_vendor) else board_vendor,
        None if bad_dmi(board_name) else board_name,
    )

    return product or board or socket.gethostname()


def get_cpu():
    model = None
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            model = line.split(":", 1)[1].strip()
            break
    return {
        "model": model,
        "cores": os.cpu_count(),
    }


def get_memory():
    mem = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            mem[k.strip()] = v.strip().replace("kB", "").strip()
    total = gib_from_kib(mem.get("MemTotal"))
    avail = gib_from_kib(mem.get("MemAvailable"))
    used = round(total - avail, 2) if total is not None and avail is not None else None
    return {
        "total_gb": total,
        "used_gb": used,
        "available_gb": avail,
    }


def get_gpu():
    if shutil.which("nvidia-smi"):
        ok, out = run([
            "nvidia-smi",
            "--query-gpu=name",
            "--format=csv,noheader"
        ])
        if ok and out:
            return list(dict.fromkeys([x.strip() for x in out.splitlines() if x.strip()]))

    if shutil.which("lspci"):
        ok, out = run(["lspci"])
        if ok and out:
            gpus = []
            for line in out.splitlines():
                low = line.lower()
                if "vga compatible controller" in low or "3d controller" in low or "display controller" in low:
                    parts = line.split(": ", 2)
                    gpus.append(parts[-1].strip())
            return gpus or None
    return None


def get_ip():
    ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return ip


def get_package_manager():
    for x in ["apt", "dnf", "yum", "pacman", "zypper", "apk", "emerge", "xbps-install"]:
        p = shutil.which(x)
        if p:
            return x
    return None


def get_shell():
    default_shell = os.environ.get("SHELL")
    current_shell = None
    try:
        ppid = os.getppid()
        current_shell = read_text(f"/proc/{ppid}/comm") or None
    except Exception:
        pass
    return {
        "default": default_shell,
        "current": current_shell,
    }


def get_desktop():
    has_desktop = bool(
        os.environ.get("DISPLAY") or
        os.environ.get("WAYLAND_DISPLAY") or
        os.environ.get("XDG_CURRENT_DESKTOP") or
        os.environ.get("DESKTOP_SESSION")
    )

    resolution = None
    if os.environ.get("DISPLAY") and shutil.which("xrandr"):
        ok, out = run(["xrandr", "--current"])
        if ok and out:
            for line in out.splitlines():
                if " connected" in line:
                    parts = line.split()
                    for p in parts:
                        if "x" in p and "+" in p:
                            resolution = p
                            break
                    if resolution:
                        break

    if not resolution and os.environ.get("DISPLAY") and shutil.which("xdpyinfo"):
        ok, out = run(["xdpyinfo"])
        if ok and out:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("dimensions:"):
                    resolution = line.split(":", 1)[1].strip().split()[0]
                    break

    return {
        "has_desktop": has_desktop,
        "resolution": resolution,
    }


def get_user():
    return {
        "user": getpass.getuser(),
        "is_root": os.geteuid() == 0,
        "cwd": os.getcwd(),
    }


def get_process():
    pid = os.getpid()
    ppid = os.getppid()
    return {
        "pid": pid,
        "ppid": ppid,
        "name": read_text(f"/proc/{pid}/comm") or None,
        "cmdline": read_text(f"/proc/{pid}/cmdline").replace("\x00", " ").strip() or None,
        "exe": os.path.realpath(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else None,
    }


data = {
    "os": get_os(),
    "kernel": get_kernel(),
    "hostname": socket.gethostname(),
    "host": get_host(),
    "cpu": get_cpu(),
    "memory": get_memory(),
    "gpu": get_gpu(),
    "ip": get_ip(),
    "python": {
        "version": platform.python_version(),
        "executable": sys.executable,
    },
    "package_manager": get_package_manager(),
    "shell": get_shell(),
    "desktop": get_desktop(),
    "user": get_user(),
    "process": get_process(),
}

print(json.dumps(data, ensure_ascii=False, indent=2))