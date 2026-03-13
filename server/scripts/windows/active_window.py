# retrieve the title and process ID of the currently active window
import ctypes
from ctypes import wintypes

import pyautogui

print(pyautogui.getActiveWindowTitle())

user32 = ctypes.windll.user32
h_wnd = user32.GetForegroundWindow()
pid = wintypes.DWORD()
user32.GetWindowThreadProcessId(h_wnd, ctypes.byref(pid))
print(pid.value)
