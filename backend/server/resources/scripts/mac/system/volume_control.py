SCRIPT_METADATA = {
    "name": "macos/device/volume_control",
    "display_name": "Volume Control",
    "description": "Get or set the system output volume on macOS",
    "platforms": ["macos"],
    "category": "Device",
    "params": [
        {
            "name": "action",
            "type": "select",
            "required": False,
            "default": "get",
            "options": ["get", "set"],
            "description": "Get current volume or set a new volume level"
        },
        {
            "name": "level",
            "type": "number",
            "required": False,
            "default": 50,
            "description": "Volume level (0-100), only used when action is 'set'"
        }
    ]
}

import subprocess

action = kwargs.get('action', 'get')

if action == 'get':
    result = subprocess.run(
        ['osascript', '-e', 'output volume of (get volume settings)'],
        capture_output=True,
        text=True
    )
    current = result.stdout.strip()
    print(f'Current volume: {current}')

elif action == 'set':
    level = kwargs.get('level', 50)
    level = int(level)
    if level < 0:
        level = 0
    elif level > 100:
        level = 100

    subprocess.run(
        ['osascript', '-e', f'set volume output volume {level}'],
        capture_output=True
    )
    print(f'Volume set to {level}')