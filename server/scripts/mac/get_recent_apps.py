#!/usr/bin/env python3
import subprocess
import json
import sys


def get_recent_apps():
    """获取最近活跃的应用排行"""
    apps = []

    try:
        # 使用AppleScript直接获取前台应用和最近使用的应用
        script = '''
        tell application "System Events"
            set recentApps to {}

            -- 获取所有前台应用的历史记录
            set frontAppHistory to {}
            set allProcesses to every application process whose background only is false

            -- 按激活时间排序
            repeat with proc in allProcesses
                set procName to name of proc
                if procName is not "Finder" and procName is not "Dock" then
                    set end of recentApps to procName
                end if
            end repeat

            return recentApps
        end tell
        '''

        result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=5)

        if result.stdout.strip():
            # 解析应用列表
            app_list = [app.strip().strip('"') for app in result.stdout.strip().split(',')]

            # 过滤掉系统进程
            exclude = {"Finder", "Dock", "SystemUIServer", "NotificationCenter", "Spotlight", "Siri"}

            for i, app in enumerate(app_list[:20], 1):
                if app and app not in exclude and not app.startswith("com."):
                    apps.append({
                        "name": app,
                        "rank": i,
                        "is_running": True
                    })

        # 如果没有获取到，获取当前前台应用
        if not apps:
            front_script = '''
            tell application "System Events"
                return name of first application process whose frontmost is true
            end tell
            '''

            front_result = subprocess.run(['osascript', '-e', front_script], capture_output=True, text=True)
            front_app = front_result.stdout.strip()

            if front_app:
                apps.append({
                    "name": front_app,
                    "rank": 1,
                    "is_frontmost": True
                })

    except Exception as e:
        return [{"error": str(e)}]

    return apps


result = get_recent_apps()
print(json.dumps(result, indent=2, ensure_ascii=False))



