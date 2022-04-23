import ctypes
from ctypes import wintypes

import win32process


class WER_REPORT_INFORMATION(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD),
                ('hProcess', wintypes.HANDLE),
                ('wzConsentKey', wintypes.WCHAR * 64),
                ('wzFriendlyEventName', wintypes.WCHAR * 128),
                ('wzApplicationName', wintypes.WCHAR * 128),
                ('wzApplicationPath', wintypes.WCHAR * wintypes.MAX_PATH),
                ('wzDescription', wintypes.WCHAR * 512),
                ('hwndParent', wintypes.HWND)]


def report_error(exec_path):
    handle_report = wintypes.HANDLE()
    wri = WER_REPORT_INFORMATION()
    wri.dwSize = ctypes.sizeof(wri)
    wri.hProcess = win32process.GetCurrentProcess()
    wri.wzApplicationPath = exec_path
    ctypes.windll.wer.WerReportCreate('pwzEventType', 3, ctypes.byref(wri), ctypes.byref(handle_report))
    ctypes.windll.wer.WerReportSetUIOption(handle_report, 2, exec_path)
    ctypes.windll.wer.WerReportSubmit(handle_report, 4, 0, ctypes.byref(wri))
    ctypes.windll.wer.WerReportCloseHandle(handle_report)
