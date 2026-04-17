SCRIPT_METADATA = {
    "name": "mac/network/get_wifi_info",
    "display_name": "Get Wi-Fi Info",
    "description": "Get current and saved Wi-Fi networks on macOS",
    "platforms": ["darwin"],
    "category": "Network",
    "params": []
}

import json
import re
import subprocess

result = {
    "current_network": None,
    "known_networks": []
}


def get_wifi_interface():
    try:
        output = subprocess.check_output(
            ["networksetup", "-listallhardwareports"],
            text=True
        )

        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "AirPort" in line or "Wi-Fi" in line:
                if i + 1 < len(lines) and "Device:" in lines[i + 1]:
                    return lines[i + 1].split(":", 1)[1].strip()
    except Exception:
        pass

    return None


def get_current_wifi():
    wifi_interface = get_wifi_interface()
    if not wifi_interface:
        result["current_network"] = "未连接或无法获取"
        return

    try:
        output = subprocess.check_output(
            ["networksetup", "-getairportnetwork", wifi_interface],
            text=True
        )

        if "Current Wi-Fi Network:" in output:
            result["current_network"] = output.split(":", 1)[1].strip()
        else:
            result["current_network"] = "未连接或无法获取"
    except Exception:
        result["current_network"] = "未连接或无法获取"


def get_wifi_history():
    wifi_interface = get_wifi_interface()

    if wifi_interface:
        try:
            output = subprocess.check_output(
                ["networksetup", "-listpreferredwirelessnetworks", wifi_interface],
                text=True
            )

            lines = output.splitlines()[1:]
            for line in lines:
                ssid = line.strip()
                if ssid:
                    result["known_networks"].append(ssid)
        except Exception:
            pass

    if not result["known_networks"]:
        try:
            output = subprocess.check_output(
                ["defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            ssids = re.findall(r'SSIDString = "([^"]+)"', output)
            result["known_networks"] = ssids
        except Exception:
            pass

    result["known_networks"] = sorted(set(result["known_networks"]), key=str.lower)


get_current_wifi()
get_wifi_history()
print(json.dumps(result, indent=2, ensure_ascii=False))