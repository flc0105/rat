#!/usr/bin/env python3
import subprocess
import json
import platform


# ======================
# scan
# ======================
def scan_macos():
    try:
        result = subprocess.run(
            ['system_profiler', 'SPUSBDataType', '-json'],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except Exception:
        return {}


def scan_linux():
    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True)
        return result.stdout
    except Exception:
        return ""


# ======================
# macOS（核心优化）
# ======================
def flatten_macos(items, path=""):
    result = []

    for item in items:
        name = item.get("_name", "Unknown")

        current_path = f"{path} > {name}" if path else name

        result.append({
            "name": name,
            "vendor": item.get("manufacturer", ""),
            "vendor_id": item.get("vendor_id", ""),
            "product_id": item.get("product_id", ""),
            "path": current_path
        })

        # 递归子设备
        if "_items" in item:
            result.extend(flatten_macos(item["_items"], current_path))

    return result


def parse_macos(data):
    try:
        items = data.get("SPUSBDataType", [])
        flat = flatten_macos(items)

        # 过滤掉“纯节点”（没有 vendor 的）
        return [d for d in flat if d["vendor"] or d["product_id"]]
    except Exception:
        return []


# ======================
# Linux（精简版）
# ======================
def parse_linux(output):
    devices = []

    for line in output.splitlines():
        if not line:
            continue

        # Bus 001 Device 002: ID 8087:0024 Intel Corp.
        parts = line.split()

        if len(parts) < 6:
            continue

        vid_pid = parts[5].split(':') if ':' in parts[5] else ["", ""]

        devices.append({
            "name": " ".join(parts[6:]),
            "vendor": "",
            "vendor_id": vid_pid[0],
            "product_id": vid_pid[1] if len(vid_pid) > 1 else "",
            "path": f"Bus {parts[1]} Device {parts[3].rstrip(':')}"
        })

    return devices


# ======================
# run
# ======================
system = platform.system()

if system == "Darwin":
    raw = scan_macos()
    data = parse_macos(raw)

elif system == "Linux":
    raw = scan_linux()
    data = parse_linux(raw)

else:
    data = {"error": f"{system} not supported"}

print(json.dumps(data, ensure_ascii=False, indent=2))