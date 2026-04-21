SCRIPT_METADATA = {
    "name": "ios/photos/upload_latest_screenshot",
    "display_name": "Upload Latest Screenshot",
    "description": "Find the latest screenshot in iOS Photos and upload it to server",
    "platforms": ["ios"],
    "category": "Photos",
    "params": []
}

import io
import json
import os
from datetime import datetime

import photos
import requests

from client.config.config import UPLOAD_BASE_URL
from core.utils.client_util import upload_file_via_http

UPLOAD_URL = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'

UTI_EXT = {
    'public.jpeg': '.jpg',
    'public.png': '.png',
    'public.heic': '.heic',
    'public.heif': '.heif',
    'com.compuserve.gif': '.gif',
    'public.tiff': '.tif',
}

def asset_datetime(asset):
    return asset.creation_date or asset.modification_date or datetime.now()

def guess_ext(data_io):
    uti = getattr(data_io, 'uti', None)
    return UTI_EXT.get(uti, '.jpg')

def get_latest_screenshot_asset():
    album = photos.get_screenshots_album()
    if album is None:
        raise RuntimeError('未找到截图相册')

    assets = list(album.assets)
    if not assets:
        raise RuntimeError('截图相册为空')

    assets.sort(key=asset_datetime)
    return assets[-1]


def main():
    asset = get_latest_screenshot_asset()
    data_io = asset.get_image_data(original=False)
    ext = guess_ext(data_io)

    dt = asset_datetime(asset).strftime('%Y%m%d_%H%M%S')
    filename = f'SCREENSHOT_{dt}{ext}'

    buf = io.BytesIO(data_io.getvalue())
    buf.name = filename

    ctx = kwargs.get('__context__', {})
    client_id = ctx.get('client_id', '')

    resp = upload_file_via_http(buf, filename=filename, upload_url=UPLOAD_URL, category='Pythonista', client_id=client_id)

    try:
        payload = resp.json()
    except Exception:
        payload = resp.text

    print(json.dumps({
        'ok': bool(resp.ok),
        'status_code': int(resp.status_code),
        'filename': filename,
        'local_id': str(getattr(asset, 'local_id', '') or ''),
        'response': payload,
    }, ensure_ascii=False, indent=2))

main()