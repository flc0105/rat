SCRIPT_METADATA = {
    "name": "win/ntdll/shutdown",
    "display_name": "Force Shutdown",
    "description": "Immediately force shutdown or restart the Windows system without warning",
    "platforms": ["windows"],
    "category": "ntdll",
    "params": [
        {
            "name": "action",
            "type": "select",
            "required": False,
            "default": "shutdown",
            "options": ["shutdown", "reboot"],
            "description": "Shutdown action: shutdown (power off) or reboot (restart)"
        }
    ]
}

import ctypes

action = kwargs.get('action', 'shutdown')
action_code = 1 if action.lower() == 'reboot' else 2

try:
    print(f'{"Rebooting" if action_code == 1 else "Shutting down"}...')
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.ZwShutdownSystem(action_code)

except Exception as e:
    print(f'Failed: {e}')