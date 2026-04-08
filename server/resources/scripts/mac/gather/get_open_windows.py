#!/usr/bin/env python3
import json
import subprocess

from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID


def get_app_path(pid):
    """通过PID获取应用路径"""
    try:
        result = subprocess.run(['lsof', '-p', str(pid), '-Fn'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.startswith('n/'):
                path = line[1:]
                if '.app/' in path:
                    # 提取.app路径
                    app_path = path.split('.app/')[0] + '.app'
                    return app_path
    except:
        pass

    return ""


def get_window_titles():
    windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionAll,
        kCGNullWindowID
    )

    result = []
    seen = set()  # 去重

    for window in windows:
        if window.get('kCGWindowName'):
            app_name = window.get('kCGWindowOwnerName', 'Unknown')
            pid = window.get('kCGWindowOwnerPID', 0)
            window_title = window['kCGWindowName']

            # 去重
            key = f"{app_name}|{window_title}"
            if key in seen:
                continue
            seen.add(key)

            # 获取应用路径
            app_path = get_app_path(pid)

            result.append({
                'app_name': app_name,
                'app_path': app_path,
                'pid': pid,
                'window_title': window_title
            })

    return result


print('Listing open windows...')
result = get_window_titles()
print(json.dumps(result, indent=2, ensure_ascii=False))




# import subprocess
#
# from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID
# import json
#
#
# def get_window_titles():
#     windows = CGWindowListCopyWindowInfo(
#         kCGWindowListOptionAll,
#         kCGNullWindowID
#     )
#
#     result = []
#     for window in windows:
#         if window.get('kCGWindowName'):
#             result.append({
#                 'app': window.get('kCGWindowOwnerName', 'Unknown'),
#                 'title': window['kCGWindowName'],
#                 'pid': window.get('kCGWindowOwnerPID', 0)
#             })
#     return result
#
#
# print(json.dumps(get_window_titles(), indent=2, ensure_ascii=False))