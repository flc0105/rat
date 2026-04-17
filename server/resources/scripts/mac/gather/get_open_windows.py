SCRIPT_METADATA = {
    "name": "mac/gather/get_open_windows",
    "display_name": "List Windows",
    "description": "List open windows on macOS",
    "platforms": ["darwin"],
    "category": "Gather",
    "params": []
}

import json
import subprocess

from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID


def get_app_path(pid):
    """通过 PID 获取应用路径"""
    try:
        result = subprocess.run(
            ["lsof", "-p", str(pid), "-Fn"],
            capture_output=True,
            text=True
        )

        for line in result.stdout.splitlines():
            if line.startswith("n/"):
                path = line[1:]
                if ".app/" in path:
                    return path.split(".app/")[0] + ".app"
    except Exception:
        pass

    return ""


def list_windows():
    windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionAll,
        kCGNullWindowID
    )

    result = []
    seen = set()

    for window in windows:
        window_title = (window.get("kCGWindowName") or "").strip()
        if not window_title:
            continue

        app_name = (window.get("kCGWindowOwnerName") or "Unknown").strip()
        pid = window.get("kCGWindowOwnerPID", 0)

        key = (pid, app_name, window_title)
        if key in seen:
            continue
        seen.add(key)

        result.append({
            "app_name": app_name,
            "app_path": get_app_path(pid),
            "pid": pid,
            "window_title": window_title
        })

    return result

print('Listing open windows...')
result = list_windows()
print(json.dumps(result, indent=2, ensure_ascii=False))