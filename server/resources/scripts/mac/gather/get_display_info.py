#!/usr/bin/env python3
import json
import subprocess


result = subprocess.run(
    ["system_profiler", "SPDisplaysDataType", "-json"],
    capture_output=True,
    text=True,
    check=True,
)

raw = json.loads(result.stdout)
items = raw.get("SPDisplaysDataType", [])

displays = []
for gpu in items:
    gpu_name = gpu.get("sppci_model")
    gpu_vendor = gpu.get("spdisplays_vendor")
    gpu_vram = (
        gpu.get("spdisplays_vram")
        or gpu.get("spdisplays_vram_shared")
        or gpu.get("spdisplays_vram_dynamic")
    )

    for display in gpu.get("spdisplays_ndrvs", []):
        displays.append({
            "name": display.get("_name"),
            "gpu_name": gpu_name,
            "gpu_vendor": gpu_vendor,
            "gpu_vram": gpu_vram,
            "display_type": display.get("spdisplays_display_type"),
            "resolution": display.get("_spdisplays_resolution"),
            "retina": display.get("spdisplays_retina") == "spdisplays_yes",
            "main": display.get("spdisplays_main") == "spdisplays_yes",
            "built_in": display.get("spdisplays_builtin") == "spdisplays_yes",
            "connection": display.get("spdisplays_connection_type"),
            "online": display.get("spdisplays_online") == "spdisplays_yes",
        })

print(json.dumps(displays, ensure_ascii=False, indent=2))