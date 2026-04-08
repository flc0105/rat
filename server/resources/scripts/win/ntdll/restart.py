import ctypes

try:
    print('Restarting...')
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.ZwShutdownSystem(1)

except Exception as e:
    print(f'Failed to restart: {e}')
