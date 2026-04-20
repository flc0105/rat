# photo_export_rename.py
import os
import re
import io
import photos
from datetime import datetime

EXPORT_DIR = os.path.expanduser('~/Documents/photo_export')

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

def safe_name(name):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name)

def unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    n = 1
    while True:
        p = f'{stem}_{n}{ext}'
        if not os.path.exists(p):
            return p
        n += 1

def guess_ext(asset, data_io):
    uti = getattr(data_io, 'uti', None)
    if uti in UTI_EXT:
        return UTI_EXT[uti]
    return '.jpg'

def export_assets(limit=None, originals=True):
    ensure_dir(EXPORT_DIR)
    assets = photos.get_assets(media_type='image')
    if limit:
        assets = assets[-limit:]

    count = 0
    for asset in assets:
        dt = asset.creation_date or asset.modification_date or datetime.now()
        ts = dt.strftime('%Y%m%d_%H%M%S')

        data_io = asset.get_image_data(original=originals)
        ext = guess_ext(asset, data_io)

        # 同一秒内多张照片时,用 local_id 末尾做区分
        suffix = safe_name(asset.local_id.split('/')[0])[-6:]
        filename = f'IMG_{ts}_{suffix}{ext}'
        path = unique_path(os.path.join(EXPORT_DIR, filename))

        with open(path, 'wb') as f:
            f.write(data_io.getvalue())

        print(path)
        count += 1

    print(f'\nexported: {count} file(s) -> {EXPORT_DIR}')

if __name__ == '__main__':
    export_assets(limit=5, originals=True)
