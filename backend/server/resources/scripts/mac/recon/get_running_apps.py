SCRIPT_METADATA = {
    "name": "mac/gather/get_running_apps",
    "display_name": "List Running Apps",
    "description": "List running macOS GUI apps with PID, user, executable path, and frontmost status",
    "platforms": ["darwin"],
    "category": "Gather",
    "params": []
}

import subprocess
import json


def get_ps_info():
    """获取 pid -> exec_path 映射"""
    info = {}
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,comm="],
            capture_output=True,
            text=True,
            timeout=5
        )

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split(None, 1)
            if len(parts) != 2:
                continue

            pid_str, comm = parts
            try:
                pid = int(pid_str)
            except ValueError:
                continue

            info[pid] = {"exec_path": comm}
    except Exception:
        pass

    return info


def list_running_apps():
    """获取当前运行中的 macOS GUI 应用"""
    apps = []

    try:
        script = r'''
        tell application "System Events"
            set outputText to ""
            set appProcs to every application process whose background only is false

            repeat with proc in appProcs
                try
                    set procName to name of proc
                    set procPid to unix id of proc
                    set procFrontmost to frontmost of proc
                    set outputText to outputText & procName & "||" & procPid & "||" & procFrontmost & linefeed
                end try
            end repeat

            return outputText
        end tell
        '''

        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=5
        )

        ps_info = get_ps_info()
        exclude = {"Finder", "Dock", "SystemUIServer", "NotificationCenter", "Spotlight", "Siri"}
        seen = set()

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("||")
            if len(parts) != 3:
                continue

            name, pid_str, frontmost_str = [p.strip() for p in parts]

            if not name or name in exclude:
                continue

            try:
                pid = int(pid_str)
            except ValueError:
                pid = None

            key = (name, pid)
            if key in seen:
                continue
            seen.add(key)

            apps.append({
                "name": name,
                "pid": pid,
                "exec_path": ps_info.get(pid, {}).get("exec_path"),
                "is_frontmost": frontmost_str.lower() == "true"
            })

    except Exception as e:
        return [{"error": str(e)}]

    return apps


result = list_running_apps()
print(json.dumps(result, indent=2, ensure_ascii=False))