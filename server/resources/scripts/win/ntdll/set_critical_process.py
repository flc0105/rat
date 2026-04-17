SCRIPT_METADATA = {
    "name": "win/ntdll/set_critical_process",
    "display_name": "Set Critical Process",
    "description": "Mark the current process as critical - terminating it will cause a system blue screen (BSOD)",
    "platforms": ["windows"],
    "category": "System",
    "params": [
        {
            "name": "enable",
            "type": "boolean",
            "required": False,
            "default": True,
            "description": "Enable or disable critical process status"
        }
    ]
}

import ctypes

enable = kwargs.get('enable', True)

ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
result = ctypes.windll.ntdll.RtlSetProcessIsCritical(enable, 0, 0)
print(result)