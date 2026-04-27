SCRIPT_METADATA = {
    "name": "win/gather/list_running_apps",
    "display_name": "List Running Apps",
    "description": "List running Windows GUI apps with PID and executable path",
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


def list_running_apps():
    apps = []
    seen_pids = set()

    def enum_window_callback(hwnd, pids):
        try:
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid and pid not in pids:
                    pids.append(pid)
        except Exception:
            pass

    window_pids = []
    try:
        win32gui.EnumWindows(enum_window_callback, window_pids)

        for pid in window_pids:
            if pid in seen_pids:
                continue
            seen_pids.add(pid)

            try:
                proc = psutil.Process(pid)

                name = _safe_proc_value(proc.name, "") or ""
                exec_path = _safe_proc_value(proc.exe, "") or ""

                if not name:
                    continue

                apps.append({
                    "name": name,
                    "pid": pid,
                    "exec_path": exec_path
                })
            except Exception:
                continue

    except Exception as e:
        return [{"error": str(e)}]

    return apps


result = list_running_apps()
print(json.dumps(result, indent=2, ensure_ascii=False))