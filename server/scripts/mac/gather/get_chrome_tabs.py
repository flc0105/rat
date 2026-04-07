#!/usr/bin/env python3
import subprocess
import json
import re


def get_chrome_tabs():
    """获取Chrome浏览器打开的标签页"""
    tabs = []

    # 首先检查Chrome是否运行
    check_script = '''
    tell application "System Events"
        return (exists process "Google Chrome")
    end tell
    '''

    check_result = subprocess.run(['osascript', '-e', check_script], capture_output=True, text=True)

    if "false" in check_result.stdout.lower():
        return [{"error": "Google Chrome is not running"}]

    try:
        # 使用更可靠的方法：逐窗口逐标签页获取，避免数据截断
        script = '''
        tell application "Google Chrome"
            set allTabs to {}
            set windowCount to count of windows

            repeat with i from 1 to windowCount
                set currentWindow to window i
                set tabCount to count of tabs of currentWindow

                repeat with j from 1 to tabCount
                    set currentTab to tab j of currentWindow
                    set tabTitle to title of currentTab
                    set tabURL to URL of currentTab

                    -- 使用特殊分隔符，避免与内容冲突
                    set tabEntry to (tabTitle as string) & "§§§" & (tabURL as string) & "§§§" & i
                    set end of allTabs to tabEntry
                end repeat
            end repeat

            -- 使用换行符分隔每个标签页
            set AppleScript's text item delimiters to "\n"
            return allTabs as string
        end tell
        '''

        result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=10)

        if result.stdout.strip() and not result.stderr:
            # 按行分割
            lines = result.stdout.strip().split('\n')

            for line in lines:
                if line and "§§§" in line:
                    parts = line.split("§§§")
                    if len(parts) >= 3:
                        title = parts[0]
                        url = parts[1]
                        window_id = parts[2]

                        # 过滤掉无意义的标签页
                        if title and title != "新标签页" and "chrome://" not in url and "chrome-extension://" not in url:
                            tabs.append({
                                "title": title,
                                "url": url,
                                "window_id": int(window_id) if window_id.isdigit() else 0
                            })

        # 如果还是没有获取到标签页，尝试使用JavaScript方式
        if not tabs:
            print("尝试备用方法...")
            js_script = '''
            tell application "Google Chrome"
                activate
                set tabInfo to {}
                set windowList to every window
                repeat with w in windowList
                    set tabList to every tab of w
                    repeat with t in tabList
                        set tabTitle to title of t
                        set tabURL to URL of t
                        set end of tabInfo to tabTitle & "|" & tabURL
                    end repeat
                end repeat
                return tabInfo
            end tell
            '''

            js_result = subprocess.run(['osascript', '-e', js_script], capture_output=True, text=True, timeout=10)

            if js_result.stdout.strip():
                # 解析结果
                lines = js_result.stdout.strip().split(', ')
                for line in lines:
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 2:
                            title = parts[0].strip('"')
                            url = parts[1].strip('"')
                            if title and url:
                                tabs.append({
                                    "title": title,
                                    "url": url
                                })

        # 如果还没有获取到，尝试使用系统事件
        if not tabs:
            print("尝试最后一种方法...")
            sys_script = '''
            tell application "System Events"
                tell process "Google Chrome"
                    set windowTitles to {}
                    repeat with w in windows
                        set tabTitles to value of static text of UI element 1 of rows of outline 1 of splitter group 1 of window w
                        repeat with tabTitle in tabTitles
                            set end of windowTitles to tabTitle
                        end repeat
                    end repeat
                    return windowTitles
                end tell
            end tell
            '''

            sys_result = subprocess.run(['osascript', '-e', sys_script], capture_output=True, text=True, timeout=10)

            if sys_result.stdout.strip():
                titles = [t.strip('"') for t in sys_result.stdout.strip().split(', ')]
                for title in titles:
                    if title:
                        tabs.append({
                            "title": title,
                            "url": "Unknown (无法获取URL)",
                            "note": "仅获取到标题"
                        })

    except subprocess.TimeoutExpired:
        tabs = [{"error": "Timeout while fetching Chrome tabs"}]
    except Exception as e:
        tabs = [{"error": f"Error: {str(e)}"}]

    return tabs


result = get_chrome_tabs()
print(json.dumps(result, indent=2, ensure_ascii=False))