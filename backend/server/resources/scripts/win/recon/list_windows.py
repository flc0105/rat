SCRIPT_METADATA = {
    "name": "win/gather/list_windows",
    "display_name": "List Windows",
    "description": "List visible top-level windows with window title, PID, process name, and executable path",
    "platforms": ["windows"],
    "category": "Gather",
    "params": []
}

import json
import psutil
import win32gui
import win32process


def _safe_proc_value(method, default=None):
    try:
        return method()
    except Exception:
        return default


def list_windows():
    windows = []

    def enum_window_callback(hwnd, results):
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return

            title = win32gui.GetWindowText(hwnd)
            if not title or not title.strip():
                return

            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if not pid:
                return

            name = ""
            exec_path = ""

            try:
                proc = psutil.Process(pid)
                name = _safe_proc_value(proc.name, "") or ""
                exec_path = _safe_proc_value(proc.exe, "") or ""
            except Exception:
                pass

            results.append({
                "title": title.strip(),
                "pid": pid,
                "name": name,
                "exec_path": exec_path
            })

        except Exception:
            pass

    try:
        win32gui.EnumWindows(enum_window_callback, windows)
    except Exception as e:
        return [{"error": str(e)}]

    return windows


result = list_windows()
print(json.dumps(result, indent=2, ensure_ascii=False))