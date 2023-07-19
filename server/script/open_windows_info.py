import psutil
import win32api
import win32con
import win32gui
import win32process

from common.util import format_dict


def get_windows():
    windows = []
    win32gui.EnumWindows(lambda hwnd, windows: windows.append(hwnd), windows)
    return windows


def get_process_info(hwnd):
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
    process_info = {'pid': pid, 'name': psutil.Process(pid).name(), 'path': psutil.Process(pid).exe(),
                    'arg': psutil.Process(pid).cmdline()[1:], 'className': win32gui.GetClassName(hwnd),
                    'title': win32gui.GetWindowText(hwnd)}
    win32api.CloseHandle(process_handle)
    return process_info


for hwnd in get_windows():
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
        process_info = get_process_info(hwnd)
        print(format_dict(process_info) + '\n')
