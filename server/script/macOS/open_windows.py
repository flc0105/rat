from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID
import json


def get_window_titles():
    windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionAll,
        kCGNullWindowID
    )

    result = []
    for window in windows:
        if window.get('kCGWindowName'):
            result.append({
                'app': window.get('kCGWindowOwnerName', 'Unknown'),
                'title': window['kCGWindowName'],
                'pid': window.get('kCGWindowOwnerPID', 0)
            })
    return result


print(json.dumps(get_window_titles(), indent=2, ensure_ascii=False))
