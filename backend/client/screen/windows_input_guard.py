import os
import time


class WindowsScreenInputGuard:
    """
    Windows Screen Control 输入保护。

    普通权限进程不能通过 UIPI 向更高完整性级别窗口注入输入。
    在真正调用 PyAutoGUI 前拦截这类目标，避免控制进入不可恢复的高权限前台窗口。
    """

    CACHE_TTL_SECONDS = 2.0

    def __init__(self):
        self._process_integrity_cache = {}
        self._self_pid = os.getpid()
        self._self_integrity = self._get_process_integrity(self._self_pid)

    def ensure_allowed(self, *, action: str, x=None, y=None):
        self._ensure_interactive_desktop()

        if self._self_integrity is None:
            raise RuntimeError(
                'Screen control paused: unable to determine the RCH client Windows integrity level.'
            )

        for hwnd in self._resolve_target_windows(action=action, x=x, y=y):
            target_pid = self._get_window_process_id(hwnd)
            if not target_pid or target_pid == self._self_pid:
                continue

            target_integrity = self._get_cached_process_integrity(target_pid)
            if target_integrity is None:
                raise RuntimeError(
                    'Screen control paused: Windows would not allow the target window permissions to be checked.'
                )

            if target_integrity > self._self_integrity:
                raise RuntimeError(
                    'Screen control paused: an elevated Windows window is active or under the pointer. '
                    'Run rchclient as administrator to control elevated windows.'
                )

    @staticmethod
    def _resolve_target_windows(*, action: str, x=None, y=None):
        import win32gui

        windows = []
        try:
            foreground = win32gui.GetForegroundWindow()
            if foreground:
                windows.append(foreground)
        except Exception:
            pass

        normalized_action = str(action or '').strip().lower()
        if normalized_action.startswith('mouse_') and x is not None and y is not None:
            try:
                pointer_window = win32gui.WindowFromPoint((int(x), int(y)))
                if pointer_window and pointer_window not in windows:
                    windows.append(pointer_window)
            except Exception:
                pass

        return windows

    @staticmethod
    def _get_window_process_id(hwnd) -> int:
        try:
            import win32process
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            return int(pid or 0)
        except Exception:
            return 0

    def _get_cached_process_integrity(self, pid: int):
        now = time.monotonic()
        cached = self._process_integrity_cache.get(int(pid))
        if cached and (now - cached[1]) <= self.CACHE_TTL_SECONDS:
            return cached[0]

        integrity = self._get_process_integrity(pid)
        self._process_integrity_cache[int(pid)] = (integrity, now)
        return integrity

    @staticmethod
    def _get_process_integrity(pid: int):
        import ntsecuritycon
        import win32api
        import win32con
        import win32security

        process_handle = None
        token_handle = None
        try:
            process_access = getattr(win32con, 'PROCESS_QUERY_LIMITED_INFORMATION', 0x1000)
            process_handle = win32api.OpenProcess(process_access, False, int(pid))
            token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_QUERY)
            sid = win32security.GetTokenInformation(
                token_handle,
                ntsecuritycon.TokenIntegrityLevel,
            )[0]
            return int(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1))
        except Exception:
            return None
        finally:
            if token_handle is not None:
                try:
                    token_handle.Close()
                except Exception:
                    pass
            if process_handle is not None:
                try:
                    process_handle.Close()
                except Exception:
                    pass

    def _ensure_interactive_desktop(self):
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL('user32', use_last_error=True)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        DESKTOP_READOBJECTS = 0x0001
        UOI_NAME = 2

        user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        user32.OpenInputDesktop.restype = wintypes.HANDLE
        user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
        user32.GetThreadDesktop.restype = wintypes.HANDLE
        user32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetUserObjectInformationW.restype = wintypes.BOOL
        user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        user32.CloseDesktop.restype = wintypes.BOOL
        kernel32.GetCurrentThreadId.restype = wintypes.DWORD

        input_desktop = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
        if not input_desktop:
            raise RuntimeError(
                'Screen control paused: Windows secure desktop or UAC is active.'
            )

        try:
            current_desktop = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
            input_name = self._get_desktop_name(user32, input_desktop, UOI_NAME)
            current_name = self._get_desktop_name(user32, current_desktop, UOI_NAME)
            if input_name and current_name and input_name.lower() != current_name.lower():
                raise RuntimeError(
                    'Screen control paused: Windows secure desktop or UAC is active.'
                )
        finally:
            user32.CloseDesktop(input_desktop)

    @staticmethod
    def _get_desktop_name(user32, desktop_handle, uoi_name: int) -> str:
        import ctypes
        from ctypes import wintypes

        if not desktop_handle:
            return ''

        needed = wintypes.DWORD(0)
        user32.GetUserObjectInformationW(
            desktop_handle,
            uoi_name,
            None,
            0,
            ctypes.byref(needed),
        )
        if needed.value <= 0:
            return ''

        buffer = ctypes.create_unicode_buffer(max(1, needed.value // ctypes.sizeof(ctypes.c_wchar)))
        if not user32.GetUserObjectInformationW(
            desktop_handle,
            uoi_name,
            buffer,
            needed.value,
            ctypes.byref(needed),
        ):
            return ''
        return str(buffer.value or '')
