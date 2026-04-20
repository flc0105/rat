SCRIPT_METADATA = {
    "name": "ios/photos/export",
    "display_name": "Export Photos",
    "description": "Export photos from iOS Photos",
    "platforms": ["ios"],
    "category": "Photos",
    "params": [
        {"name": "recent", "type": "number", "required": False, "default": None, "description": "Only export the most recent N images"},
        {"name": "start", "type": "string", "required": False, "default": "", "description": "Start date, e.g. 2026-04-01"},
        {"name": "end", "type": "string", "required": False, "default": "", "description": "End date, e.g. 2026-04-19"},
        {"name": "album", "type": "string", "required": False, "default": "", "description": "Filter by album name"},
        {"name": "original", "type": "boolean", "required": False, "default": False, "description": "Export unmodified originals"},
    ]
}

import os
import re
from datetime import datetime, timedelta

import photos


UTI_EXT = {
    'public.jpeg': '.jpg',
    'public.png': '.png',
    'public.heic': '.heic',
    'public.heif': '.heif',
    'com.compuserve.gif': '.gif',
    'public.tiff': '.tif',
}


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def unique_path(path):
    if not os.path.exists(path):
        return path

    stem, ext = os.path.splitext(path)
    index = 1
    while True:
        candidate = f'{stem}_{index}{ext}'
        if not os.path.exists(candidate):
            return candidate
        index += 1


def safe_part(text):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', str(text or ''))


def parse_date(value):
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    for fmt in ('%Y-%m-%d', '%Y%m%d', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass

    raise ValueError(f'invalid date: {value}')


def dt_floor(dt):
    return datetime(dt.year, dt.month, dt.day, 0, 0, 0)


def dt_ceil_exclusive(dt):
    return datetime(dt.year, dt.month, dt.day, 0, 0, 0) + timedelta(days=1)


def asset_datetime(asset):
    return asset.creation_date or asset.modification_date or datetime.now()


def get_album_by_name(name):
    for album in photos.get_albums():
        if album.title == name:
            return album
    return None


def get_assets_from_source(album_name=''):
    if album_name:
        album = get_album_by_name(album_name)
        if not album:
            raise ValueError(f'album not found: {album_name}')
        return list(album.assets)

    return list(photos.get_assets(media_type='image'))


def filter_assets(assets, recent=None, start=None, end=None):
    filtered = list(assets)

    filtered = sorted(filtered, key=asset_datetime)

    if start:
        start_dt = dt_floor(start)
        filtered = [asset for asset in filtered if asset_datetime(asset) >= start_dt]

    if end:
        end_exclusive = dt_ceil_exclusive(end)
        filtered = [asset for asset in filtered if asset_datetime(asset) < end_exclusive]

    if recent is not None:
        recent_value = int(recent)
        if recent_value < 0:
            raise ValueError('recent must be >= 0')
        filtered = filtered[-recent_value:] if recent_value > 0 else []

    return filtered


def guess_ext(data_io):
    uti = getattr(data_io, 'uti', None)
    return UTI_EXT.get(uti, '.jpg')


def build_output_dir():
    root_dir = os.path.expanduser('~/Documents/photo-export')
    export_name = datetime.now().strftime('export-%Y%m%d-%H%M%S')
    out_dir = os.path.join(root_dir, export_name)
    ensure_dir(out_dir)
    return out_dir


def export_assets(assets, out_dir, originals=False):
    ensure_dir(out_dir)
    count = 0

    for asset in assets:
        dt = asset_datetime(asset)
        print('Originals: ' + str(originals))
        data_io = asset.get_image_data(original=originals)
        ext = guess_ext(data_io)
        suffix = safe_part(str(getattr(asset, 'local_id', '')).split('/')[0])[-6:]
        name = f'IMG_{dt.strftime("%Y%m%d_%H%M%S")}_{suffix}{ext}'
        path = unique_path(os.path.join(out_dir, name))

        with open(path, 'wb') as file_obj:
            file_obj.write(data_io.getvalue())

        print(path, flush=True)
        count += 1

    print(f'\nexported: {count} file(s)', flush=True)
    print(f'output_dir: {out_dir}', flush=True)
    return count


def main(kwargs):
    recent = kwargs.get('recent')
    start = parse_date(kwargs.get('start', ''))
    end = parse_date(kwargs.get('end', ''))
    album = str(kwargs.get('album', '') or '').strip()
    original = bool(kwargs.get('original', False))

    assets = get_assets_from_source(album_name=album)

    assets = filter_assets(
        assets,
        recent=recent,
        start=start,
        end=end,
    )

    if not assets:
        print('no assets matched', flush=True)
        return

    out_dir = build_output_dir()
    export_assets(
        assets,
        out_dir=out_dir,
        originals=original,
    )


main(kwargs)