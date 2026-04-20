# coding: utf-8
import ctypes
import json
import time

from objc_util import NSBundle, ObjCClass, ObjCBlock

NSBundle.bundleWithPath_('/System/Library/Frameworks/MediaPlayer.framework').load()

MPMediaLibrary = ObjCClass('MPMediaLibrary')
MPMediaQuery = ObjCClass('MPMediaQuery')

_auth_done = False
_auth_status = None
_auth_block = None


def request_media_library_access(timeout=15):
    global _auth_done, _auth_status, _auth_block

    try:
        status = MPMediaLibrary.authorizationStatus()
    except Exception:
        return None

    if status != 0:
        return int(status)

    def handler(status_value):
        global _auth_done, _auth_status
        _auth_status = int(status_value)
        _auth_done = True

    _auth_done = False
    _auth_status = None
    _auth_block = ObjCBlock(
        handler,
        restype=None,
        argtypes=[ctypes.c_long]
    )

    MPMediaLibrary.requestAuthorization_(_auth_block)

    start = time.time()
    while not _auth_done and (time.time() - start) < timeout:
        time.sleep(0.1)

    return _auth_status


def ns_to_py(x):
    if x is None:
        return ''
    try:
        return str(x)
    except Exception:
        return ''


def num_to_int(x, default=0):
    if x is None:
        return default
    try:
        return int(x)
    except Exception:
        try:
            return int(str(x))
        except Exception:
            return default


def safe_call(obj, selector_name, default=None):
    try:
        fn = getattr(obj, selector_name)
        return fn()
    except Exception:
        return default


def iter_nsarray(arr):
    if arr is None:
        return
    count = int(arr.count())
    for i in range(count):
        yield arr.objectAtIndex_(i)


def song_rows():
    query = MPMediaQuery.songsQuery()
    items = query.items()
    if items is None:
        return []

    rows = []
    for item in iter_nsarray(items):
        rows.append({
            'artist': ns_to_py(safe_call(item, 'artist', '')),
            'title': ns_to_py(safe_call(item, 'title', '')),
            'album': ns_to_py(safe_call(item, 'albumTitle', '')),
            'playCount': num_to_int(safe_call(item, 'playCount', 0), 0),
        })

    rows.sort(
        key=lambda r: (
            r['artist'].casefold(),
            r['title'].casefold(),
            r['album'].casefold(),
        )
    )
    return rows


def main():
    status = request_media_library_access()
    if status in (1, 2):
        print('没有媒体库权限。请在 iOS 设置中允许 Pythonista 访问媒体与 Apple Music。')
        return

    rows = song_rows()
    print(json.dumps(rows, ensure_ascii=False, indent=2))


main()
