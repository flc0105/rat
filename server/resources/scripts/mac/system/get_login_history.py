#!/usr/bin/env python3

SCRIPT_METADATA = {
    "name": "common/system/get_login_history",
    "display_name": "Get Login History",
    "description": "Get recent login history",
    "platforms": ["darwin", "linux"],
    "category": "System",
    "params": [
        {
            "name": "limit",
            "type": "number",
            "required": False,
            "default": 20,
            "description": "Maximum number of records to return"
        }
    ]
}

import json
import subprocess


def parse_last_output(output, limit):
    records = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("wtmp"):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        user = parts[0]
        tty = parts[1]
        login_time = " ".join(parts[2:6])

        records.append({
            "user": user,
            "tty": tty,
            "login_time": login_time
        })

        if len(records) >= limit:
            break

    return records


def main():
    limit = kwargs.get("limit", 20)
    try:
        limit = int(limit)
    except Exception:
        limit = 20

    if limit <= 0:
        limit = 20

    try:
        result = subprocess.run(
            ["last"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(json.dumps({"error": "Failed to get login history"}, ensure_ascii=False))
            return

        records = parse_last_output(result.stdout, limit)
        print(json.dumps(records, ensure_ascii=False, indent=2))

    except Exception as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))


main()