import ctypes

ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
result = ctypes.windll.ntdll.RtlSetProcessIsCritical(False, 0, 0)
print(result)
