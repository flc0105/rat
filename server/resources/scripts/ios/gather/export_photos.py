#!/usr/bin/env python3
# coding: utf-8

import os
import re
import sys
import argparse
from datetime import datetime, date, timedelta

import photos

UTI_EXT = {
    'public.jpeg': '.jpg',
    'public.png': '.png',
    'public.heic': '.heic',
    'public.heif': '.heif',
    'com.compuserve.gif': '.gif',
    'public.tiff': '.tif',
}

SCREENSHOT_SUBTYPE = getattr(photos, 'MEDIA_SUBTYPE_SCREENSHOT', 8)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 1
    while True:
        p = f'{stem}_{i}{ext}'
        if not os.path.exists(p):
            return p
        i += 1


def safe_part(text):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', text or '')


def parse_date(s):
    # 支持 YYYY-MM-DD / YYYYMMDD / YYYY-MM-DDTHH:MM:SS
    for fmt in ('%Y-%m-%d', '%Y%m%d', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f'invalid date: {s}')


def dt_floor(dt):
    return datetime(dt.year, dt.month, dt.day, 0, 0, 0)


def dt_ceil_exclusive(dt):
    return datetime(dt.year, dt.month, dt.day, 0, 0, 0) + timedelta(days=1)


def asset_datetime(asset):
    return asset.creation_date or asset.modification_date or datetime.now()


def is_screenshot(asset):
    try:
        sub = getattr(asset, 'media_subtypes', 0) or 0
        return bool(sub & SCREENSHOT_SUBTYPE)
    except Exception:
        return False


def get_album_by_name(name):
    for album in photos.get_albums():
        if album.title == name:
            return album
    return None


def get_or_create_album(name):
    album = get_album_by_name(name)
    if album:
        return album
    return photos.create_album(name)


def get_assets_from_source(album_name=None, screenshots_only=False):
    if screenshots_only:
        try:
            src = photos.get_screenshots_album()
            return list(src.assets)
        except Exception:
            # fallback: 全量后再筛
            pass

    if album_name:
        album = get_album_by_name(album_name)
        if not album:
            raise SystemExit(f'album not found: {album_name}')
        assets = list(album.assets)
    else:
        assets = list(photos.get_assets(media_type='image'))

    if screenshots_only:
        assets = [a for a in assets if is_screenshot(a)]

    return assets


def filter_assets(assets, recent=None, start=None, end=None):
    assets = sorted(assets, key=asset_datetime)

    if start:
        start = dt_floor(start)
        assets = [a for a in assets if asset_datetime(a) >= start]

    if end:
        end_exclusive = dt_ceil_exclusive(end)
        assets = [a for a in assets if asset_datetime(a) < end_exclusive]

    if recent:
        assets = assets[-recent:]

    return assets


def guess_ext(data_io):
    uti = getattr(data_io, 'uti', None)
    return UTI_EXT.get(uti, '.jpg')


def export_assets(assets, out_dir, originals=True, monthly_dirs=False, prefix='IMG'):
    ensure_dir(out_dir)
    count = 0

    for asset in assets:
        dt = asset_datetime(asset)
        base_dir = out_dir
        if monthly_dirs:
            base_dir = os.path.join(out_dir, dt.strftime('%Y-%m'))
            ensure_dir(base_dir)

        data_io = asset.get_image_data(original=originals)
        ext = guess_ext(data_io)
        suffix = safe_part(str(asset.local_id).split('/')[0])[-6:]
        name = f'{prefix}_{dt.strftime("%Y%m%d_%H%M%S")}_{suffix}{ext}'
        path = unique_path(os.path.join(base_dir, name))

        with open(path, 'wb') as f:
            f.write(data_io.getvalue())

        print(path)
        count += 1

    print(f'\nexported: {count} file(s)')
    return count


def archive_screenshots(assets, archive_album, hide=False):
    if not assets:
        print('no screenshots matched')
        return

    dst = get_or_create_album(archive_album)

    if not dst.can_add_assets:
        raise SystemExit(f'cannot add assets to album: {archive_album}')

    dst.add_assets(assets)

    hidden_count = 0
    if hide:
        for asset in assets:
            try:
                if asset.can_edit_properties and not asset.hidden:
                    asset.hidden = True
                    hidden_count += 1
            except Exception:
                pass

    print(f'archived: {len(assets)} screenshot(s) -> {archive_album}')
    if hide:
        print(f'hidden:   {hidden_count} screenshot(s)')


def build_common_filters(p):
    p.add_argument('--recent', type=int, help='仅取最近 N 张')
    p.add_argument('--start', type=parse_date, help='开始日期,如 2026-04-01')
    p.add_argument('--end', type=parse_date, help='结束日期,如 2026-04-19')
    p.add_argument('--album', help='按相册名取图')
    p.add_argument('--verbose', action='store_true')


def resolve_assets(args, screenshots_only=False):
    assets = get_assets_from_source(
        album_name=args.album,
        screenshots_only=screenshots_only,
    )
    before = len(assets)
    assets = filter_assets(
        assets,
        recent=args.recent,
        start=args.start,
        end=args.end,
    )

    if args.verbose:
        eprint(f'before filter: {before}')
        eprint(f'after filter:  {len(assets)}')

    return assets


def cmd_export(args):
    assets = resolve_assets(args, screenshots_only=False)
    if not assets:
        print('no assets matched')
        return
    export_assets(
        assets,
        out_dir=args.out,
        originals=not args.rendered,
        monthly_dirs=args.monthly_dirs,
        prefix=args.prefix,
    )


def cmd_archive_screenshots(args):
    assets = resolve_assets(args, screenshots_only=True)
    archive_screenshots(
        assets,
        archive_album=args.archive_album,
        hide=args.hide,
    )


def main():
    parser = argparse.ArgumentParser(
        description='Photo library batch tools for Pythonista'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('export', help='导出图片并按拍摄时间重命名')
    build_common_filters(p1)
    p1.add_argument('--out', default=os.path.expanduser('~/Documents/photo_export'))
    p1.add_argument('--rendered', action='store_true', help='导出渲染图,不取原始数据')
    p1.add_argument('--monthly-dirs', action='store_true', help='按 YYYY-MM 分目录')
    p1.add_argument('--prefix', default='IMG', help='输出文件名前缀')
    p1.set_defaults(func=cmd_export)

    p2 = sub.add_parser('archive-screenshots', help='筛选截图并归档到指定相册')
    build_common_filters(p2)
    p2.add_argument('--archive-album', default='Screenshots Archive')
    p2.add_argument('--hide', action='store_true', help='归档后隐藏')
    p2.set_defaults(func=cmd_archive_screenshots)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
