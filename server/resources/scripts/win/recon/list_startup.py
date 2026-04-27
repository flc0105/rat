SCRIPT_METADATA = {
    "name": "win/gather/list_startup",
    "display_name": "List Startup Items",
    "description": "Get Windows startup items",
    "platforms": ["windows"],
    "category": "Gather",
    "params": []
}

import json
import wmi

result = []
seen = set()

try:
    client = wmi.WMI()

    for item in client.Win32_StartupCommand():
        caption = (item.Caption or "").strip()
        command = (item.Command or "").strip()
        location = (item.Location or "").strip()

        unique_key = (caption, command, location)
        if unique_key in seen:
            continue
        seen.add(unique_key)

        result.append({
            "caption": caption or "N/A",
            "command": command or "N/A",
            "location": location or "N/A"
        })

    result.sort(key=lambda x: (x.get("caption") or "").lower())
    print(json.dumps(result, ensure_ascii=False, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}, ensure_ascii=False))