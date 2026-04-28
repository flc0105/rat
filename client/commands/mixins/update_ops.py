import os
import shutil

from client.commands.interrupts import interruptible
from client.config.config import (
    SERVER_HOST,
    SERVER_PORT,
    SERVER_WEB_HOST,
    SERVER_WEB_PORT,
    SERVER_WEB_SCHEME,
)
from core.platform.platform_identity import detect_platform_alias
from core.utils.client_util import (
    build_bundle_extract_dir,
    get_client_bundle_release_dir,
    safe_extract_zip_file,
    spawn_detached_python_script,
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
        return self.client_api.build_agent_bundle(
            self._build_update_request_payload(),
            timeout=self.BUILD_API_TIMEOUT,
        )

    def _download_bundle_archive(self, download_url: str, archive_path: str):
        self.client_api.download_file(
            download_url,
            archive_path,
            timeout=self.DOWNLOAD_TIMEOUT,
            chunk_size=self.DOWNLOAD_CHUNK_SIZE,
            ensure_not_interrupted=self._ensure_not_interrupted,
        )

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
            if detect_platform_alias() != 'ios':
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