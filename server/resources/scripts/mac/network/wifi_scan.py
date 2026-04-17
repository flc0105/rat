SCRIPT_METADATA = {
    "name": "mac/network/wifi_scan",
    "display_name": "Scan Wi-Fi",
    "description": "Scan nearby Wi-Fi networks",
    "platforms": ["darwin"],
    "category": "Network",
    "params": []
}

import subprocess
import json
import platform
import re


def scan_macos():
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception:
        return ""


def scan_linux():
    try:
        subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True)
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "device", "wifi", "list"],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception:
        return ""


def parse_macos(output):
    networks = []

    lines = output.splitlines()
    if len(lines) < 2:
        return networks

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        rssi_index = None
        rssi_val = None

        for i, p in enumerate(parts):
            if re.fullmatch(r"-?\d+", p):
                rssi_index = i
                rssi_val = int(p)
                break

        if rssi_index is None:
            continue

        ssid = " ".join(parts[:rssi_index]).strip()
        security = parts[-1].strip()
        signal = max(0, min(100, 2 * (rssi_val + 100)))

        networks.append({
            "ssid": ssid or "(hidden)",
            "signal": signal,
            "security": security
        })

    return networks


def parse_linux(output):
    networks = []

    for line in output.splitlines():
        if not line:
            continue

        parts = line.split(":")
        if len(parts) < 3:
            continue

        ssid = parts[0].strip() or "(hidden)"
        security = parts[1].strip()
        signal = int(parts[2]) if parts[2].isdigit() else None

        networks.append({
            "ssid": ssid,
            "signal": signal,
            "security": security
        })

    return networks


def deduplicate(networks):
    best = {}

    for n in networks:
        ssid = n["ssid"]

        if ssid not in best:
            best[ssid] = n
        else:
            if (n["signal"] or 0) > (best[ssid]["signal"] or 0):
                best[ssid] = n

    return list(best.values())


def sort_networks(networks):
    return sorted(
        networks,
        key=lambda x: (x["signal"] is not None, x["signal"] if x["signal"] is not None else -1),
        reverse=True
    )


system = platform.system()

if system == "Darwin":
    raw = scan_macos()
    networks = parse_macos(raw)
elif system == "Linux":
    raw = scan_linux()
    networks = parse_linux(raw)
else:
    print(json.dumps({"error": f"{system} not supported"}, ensure_ascii=False))
    raise SystemExit

networks = deduplicate(networks)
networks = sort_networks(networks)

print(json.dumps(networks, ensure_ascii=False, indent=2))