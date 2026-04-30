import os
import shutil
import sys

from client.commands.runtime.interrupts import interruptible
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

    def _get_current_bundle_release_dir(self, release_dir: str) -> str:
        """
        当前仅识别 update bundle 运行模式：
        ~/client_bundle/releases/<bundle_dir>/ratclient.py
        """
        if getattr(sys, 'frozen', False):
            return ''

        release_root = os.path.realpath(os.path.abspath(release_dir))
        candidates = []

        module_file = str(globals().get('__file__') or '').strip()
        if module_file:
            candidates.append(os.path.dirname(os.path.realpath(os.path.abspath(module_file))))

        argv0 = str(sys.argv[0] or '').strip()
        if argv0:
            candidates.append(os.path.dirname(os.path.realpath(os.path.abspath(argv0))))

        candidates.append(os.path.realpath(os.path.abspath(os.getcwd())))

        for current_dir in candidates:
            bundle_dir = self._resolve_bundle_release_dir_from_path(release_root, current_dir)
            if bundle_dir:
                return bundle_dir

        return ''

    def _resolve_bundle_release_dir_from_path(self, release_root: str, current_path: str) -> str:
        try:
            current_path = os.path.realpath(os.path.abspath(current_path))
            if os.path.commonpath([release_root, current_path]) != release_root:
                return ''

            relative_path = os.path.relpath(current_path, release_root)
            if not relative_path or relative_path == '.' or relative_path.startswith('..'):
                return ''

            release_name = relative_path.split(os.sep, 1)[0]
            bundle_dir = os.path.realpath(os.path.join(release_root, release_name))
            ratclient_path = os.path.join(bundle_dir, 'ratclient.py')

            if not os.path.isdir(bundle_dir):
                return ''
            if not os.path.isfile(ratclient_path):
                return ''

            return bundle_dir
        except Exception:
            return ''

    def _clean_outdated_bundle_releases(self, release_dir: str, current_bundle_dir: str) -> dict:
        release_root = os.path.realpath(os.path.abspath(release_dir))
        current_root = os.path.realpath(os.path.abspath(current_bundle_dir))

        deleted_dirs = []
        deleted_zips = []
        skipped = []
        errors = []

        for name in sorted(os.listdir(release_root)):
            self._ensure_not_interrupted()

            path = os.path.realpath(os.path.join(release_root, name))

            try:
                if os.path.isdir(path):
                    if path == current_root:
                        skipped.append(path)
                        continue
                    shutil.rmtree(path)
                    deleted_dirs.append(path)
                    continue

                if os.path.isfile(path) and name.lower().endswith('.zip'):
                    os.remove(path)
                    deleted_zips.append(path)
                    continue
            except Exception as e:
                errors.append(f'{path}: {e}')

        return {
            'release_dir': release_root,
            'current_bundle_dir': current_root,
            'deleted_dirs': deleted_dirs,
            'deleted_zips': deleted_zips,
            'skipped': skipped,
            'errors': errors,
        }

    def _format_clean_outdated_releases_result(self, result: dict) -> str:
        lines = [
            'Outdated bundle releases cleaned',
            f'Release Dir: {result.get("release_dir", "")}',
            f'Current Bundle Dir: {result.get("current_bundle_dir", "")}',
            f'Deleted Version Dirs: {len(result.get("deleted_dirs") or [])}',
            f'Deleted ZIP Files: {len(result.get("deleted_zips") or [])}',
        ]

        deleted_dirs = result.get('deleted_dirs') or []
        deleted_zips = result.get('deleted_zips') or []
        errors = result.get('errors') or []

        if deleted_dirs:
            lines.append('Deleted dirs:')
            lines.extend(f'  {item}' for item in deleted_dirs)

        if deleted_zips:
            lines.append('Deleted zips:')
            lines.extend(f'  {item}' for item in deleted_zips)

        if errors:
            lines.append('Errors:')
            lines.extend(f'  {item}' for item in errors)

        return '\n'.join(lines)

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

            if detect_platform_alias() == 'ios':

                import sys, time
                # spawn(ratclient_path)
                self._send_final_result(1, f'Update bundle downloaded\n'
                                           f'Build Version: {bundle_meta.get("build_version") or "-"}\n'
                                           f'Downloaded Archive: {archive_path}\n'
                                           f'Extracted Path: {extract_dir}\n'
                                           f'Launch Script: {ratclient_path}\n')
                # time.sleep(1)
                # self.socket.close()
                # raise SystemExit

            else:
                process = spawn_detached_python_script(ratclient_path, cwd=extract_dir)
                return 1, (
                    f'Update bundle downloaded and started\n'
                    f'Build Version: {bundle_meta.get("build_version") or "-"}\n'
                    f'Downloaded Archive: {archive_path}\n'
                    f'Extracted Path: {extract_dir}\n'
                    f'Launch Script: {ratclient_path}\n'
                    f'PID: {process.pid}'

                )
        except Exception as e:
            return 0, f'Failed to update client bundle: {e}'

    @desc('Clean outdated client bundle release directories and ZIP files', group='session')
    @interruptible()
    def clean(self, arg=''):
        """
        清理默认 releases 目录里的旧 update bundle。
        当前只在自身运行于 update bundle 目录时执行。
        """
        try:
            release_dir = get_client_bundle_release_dir()
            current_bundle_dir = self._get_current_bundle_release_dir(release_dir)
            if not current_bundle_dir:
                return 1, (
                    'Skipped: current client is not running from default update bundle releases directory\n'
                    f'Release Dir: {release_dir}'
                )

            result = self._clean_outdated_bundle_releases(release_dir, current_bundle_dir)
            return 1, self._format_clean_outdated_releases_result(result)
        except Exception as e:
            return 0, f'Failed to clean outdated releases: {e}'
