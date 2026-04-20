# coding: utf-8
# Pythonista 3
# 导出 Apple Music / 本机音乐库歌曲清单到 CSV
#
# 输出字段:
# artist,title,album,play_count,is_favorite
#
# 说明:
# 1) play_count 走 MediaPlayer 媒体库,可直接读取
# 2) is_favorite 在普通 MPMediaQuery / MPMediaItem 里没有稳定公开字段,
#    这里先统一写 unknown
#
# 首次运行可能会请求媒体库访问权限。

import os
import csv
import time
import ctypes

from objc_util import ObjCClass, ObjCBlock, nsurl, ObjCInstance

MPMediaLibrary = ObjCClass('MPMediaLibrary')
MPMediaQuery = ObjCClass('MPMediaQuery')
NSOperationQueue = ObjCClass('NSOperationQueue')

_auth_done = False
_auth_status = None
_auth_block = None


def request_media_library_access(timeout=15):
    """
    请求媒体库权限。
    返回:
      0 = notDetermined
      1 = denied
      2 = restricted
      3 = authorized
      4 = limited / newer enum variants (若系统返回)
    """
    global _auth_done, _auth_status, _auth_block

    try:
        status = MPMediaLibrary.authorizationStatus()
    except Exception:
        # 某些系统/桥接下如果这里异常,直接继续尝试查询
        return None

    if status != 0:
        return int(status)

    def handler(_cmd, status_value):
        global _auth_done, _auth_status
        _auth_status = int(status_value)
        _auth_done = True

    _auth_done = False
    _auth_status = None
    _auth_block = ObjCBlock(handler, restype=None, argtypes=[ctypes.c_void_p, ctypes.c_long])

    MPMediaLibrary.requestAuthorization(_auth_block)

    start = time.time()
    while not _auth_done and (time.time() - start) < timeout:
        time.sleep(0.1)

    return _auth_status


def ns_to_py(x):
    if x is None:
        return None
    try:
        return str(x)
    except Exception:
        return None


def num_to_int(x, default=0):
    if x is None:
        return default
    try:
        # NSNumber 在 objc_util 下通常可转 int
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
    """
    从媒体库读取歌曲。
    优先走 songsQuery;不行则退回 queries。
    """
    query = None

    # 常见 Objective-C selector 是 songsQuery
    try:
        query = MPMediaQuery.songsQuery()
    except Exception:
        pass

    if query is None:
        raise RuntimeError('无法创建 MPMediaQuery.songsQuery()')

    items = query.items()
    if items is None:
        return

    for item in iter_nsarray(items):
        # 常见属性访问器
        artist = ns_to_py(safe_call(item, 'artist', ''))
        title = ns_to_py(safe_call(item, 'title', ''))
        album = ns_to_py(safe_call(item, 'albumTitle', ''))

        play_count_raw = safe_call(item, 'playCount', 0)
        play_count = num_to_int(play_count_raw, 0)


        yield {
            'artist': artist or '',
            'title': title or '',
            'album': album or '',
            'play_count': play_count,
        }


def export_csv(out_path):
    rows = list(song_rows())
    
    rows = sorted(
      song_rows(),
      key=lambda r: (
          (r['artist'] or '').casefold(),
          (r['title'] or '').casefold(),
          (r['album'] or '').casefold(),
      )
    )

    with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['artist', 'title', 'album', 'play_count']
        )
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def main():
    out_path = os.path.expanduser('~/Documents/apple_music_songs.csv')

    status = request_media_library_access()

    # 常见状态: 1 denied, 2 restricted
    if status in (1, 2):
        raise SystemExit('没有媒体库权限。请在 iOS 设置中允许 Pythonista 访问媒体与 Apple Music。')

    count = export_csv(out_path)
    print(f'导出完成: {count} 首')
    print(out_path)


if __name__ == '__main__':
    main()
