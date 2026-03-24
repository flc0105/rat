#!/usr/bin/env python3
import json
import subprocess


def get_frontmost_app():
    # 获取前台应用名称和PID
    name_script = '''
    tell application "System Events"
        return name of first application process whose frontmost is true
    end tell
    '''

    name_result = subprocess.run(['osascript', '-e', name_script], capture_output=True, text=True)
    app_name = name_result.stdout.strip()

    if not app_name:
        return {"error": "无法获取前台应用"}

    # 获取PID
    pid_script = f'''
    tell application "System Events"
        return unix id of first application process whose frontmost is true
    end tell
    '''

    pid_result = subprocess.run(['osascript', '-e', pid_script], capture_output=True, text=True)
    pid = int(pid_result.stdout.strip()) if pid_result.stdout.strip() else 0

    # 获取路径
    path_script = f'''
    tell application "Finder"
        try
            return POSIX path of (application file id (id of application "{app_name}") as alias)
        on error
            return ""
        end try
    end tell
    '''

    path_result = subprocess.run(['osascript', '-e', path_script], capture_output=True, text=True)
    app_path = path_result.stdout.strip()

    # 获取窗口标题
    window_script = f'''
    tell application "System Events"
        try
            tell process "{app_name}"
                return name of first window
            end tell
        on error
            return ""
        end try
    end tell
    '''

    window_result = subprocess.run(['osascript', '-e', window_script], capture_output=True, text=True)
    window_title = window_result.stdout.strip()

    return {
        "app_name": app_name,
        "app_path": app_path if app_path else "未找到路径",
        "pid": pid,
        "window_title": window_title if window_title else "无窗口"
    }


result = get_frontmost_app()
print(json.dumps(result, indent=2, ensure_ascii=False))
