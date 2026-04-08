import ctypes

try:
    print('Shutting down...')
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.ZwShutdownSystem(2)

except Exception as e:
    print(f'Failed to shutdown: {e}')
