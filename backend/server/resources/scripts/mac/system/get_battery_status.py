SCRIPT_METADATA = {
    "name": "mac/system/get_battery_status",
    "display_name": "Get Battery Status",
    "description": "Get battery status on macOS",
    "platforms": ["darwin"],
    "category": "System",
    "params": []
}

import json
import re
import subprocess


def get_battery_status():
    try:
        battery_info = {}

        batt_result = subprocess.run(
            ["pmset", "-g", "batt"],
            capture_output=True,
            text=True
        )
        if batt_result.returncode != 0:
            return {"error": "No battery found or battery not available"}

        batt_output = batt_result.stdout.strip()

        match = re.search(r"(\d+)%", batt_output)
        if match:
            battery_info["percentage"] = int(match.group(1))

        if "AC Power" in batt_output:
            battery_info["state"] = "charging"
        elif "Battery Power" in batt_output:
            battery_info["state"] = "discharging"

        match = re.search(r"(\d+):(\d+) remaining", batt_output)
        if match:
            battery_info["remaining_minutes"] = int(match.group(1)) * 60 + int(match.group(2))

        power_result = subprocess.run(
            ["system_profiler", "SPPowerDataType"],
            capture_output=True,
            text=True
        )
        if power_result.returncode == 0:
            for line in power_result.stdout.splitlines():
                line = line.strip()

                match = re.search(r"Cycle Count:\s*(\d+)", line)
                if match:
                    battery_info["cycle_count"] = int(match.group(1))
                    continue

                match = re.search(r"Condition:\s*(.+)", line)
                if match:
                    battery_info["condition"] = match.group(1).strip()
                    continue

        return battery_info

    except Exception as e:
        return {"error": str(e)}


result = get_battery_status()
print(json.dumps(result, ensure_ascii=False, indent=2))