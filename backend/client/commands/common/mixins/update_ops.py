import os
import shutil
import sys
import tempfile

from client.commands.platform.utils.ios_util import spawn
from client.commands.runtime.interrupts import interruptible
from client.config.config import (
    SERVER_HOST,
    SERVER_PORT,
    SERVER_WEB_HOST,
    SERVER_WEB_PORT,
    SERVER_WEB_SCHEME,
)
from core.external_tools.archive import safe_extract_zip_archive
from core.platform.platform_identity import detect_platform_alias
from client.runtime.client_util import (
    build_bundle_extract_dir,
    get_client_bundle_release_dir,
    spawn_detached_python_script,
)
from core.utils.decorator import desc
from core.utils.output_marker import success, info, warning, error


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
        ~/client_bundle/releases/<bundle_dir>/rchclient.py
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
            rchclient_path = os.path.join(bundle_dir, 'rchclient.py')

            if not os.path.isdir(bundle_dir):
                return ''
            if not os.path.isfile(rchclient_path):
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
            success('Outdated bundle releases cleaned'),
            info(f'Release Dir: {result.get("release_dir", "")}'),
            info(f'Current Bundle Dir: {result.get("current_bundle_dir", "")}'),
            success(f'Deleted Version Dirs: {len(result.get("deleted_dirs") or [])}'),
            success(f'Deleted ZIP Files: {len(result.get("deleted_zips") or [])}'),
        ]

        deleted_dirs = result.get('deleted_dirs') or []
        deleted_zips = result.get('deleted_zips') or []
        errors = result.get('errors') or []

        if deleted_dirs:
            lines.append(warning('Deleted dirs:'))
            lines.extend(f'  {item}' for item in deleted_dirs)

        if deleted_zips:
            lines.append(warning('Deleted zips:'))
            lines.extend(f'  {item}' for item in deleted_zips)

        if errors:
            lines.append(error('Errors:'))
            lines.extend(f'  {item}' for item in errors)

        return '\n'.join(lines)


    def _same_real_path(self, left: str, right: str) -> bool:
        if not left or not right:
            return False
        try:
            return os.path.realpath(os.path.abspath(left)) == os.path.realpath(os.path.abspath(right))
        except Exception:
            return False

    def _is_extracted_bundle_usable(self, extract_dir: str) -> bool:
        rchclient_path = os.path.join(extract_dir, 'rchclient.py')
        return os.path.isdir(extract_dir) and os.path.isfile(rchclient_path)

    def _extract_update_bundle_safely(self, archive_path: str, extract_dir: str, current_bundle_dir: str = '') -> str:
        """
        安全解压 update bundle。

        原则：
        1. 已存在可用目录时直接复用，避免同名 bundle 重复解压时删除正在运行的目录。
        2. 绝不删除当前进程所在的 bundle 目录。
        3. 先解压到临时目录，校验 rchclient.py 后再发布，避免中断后留下半成品目录。
        """
        release_dir = os.path.dirname(os.path.realpath(os.path.abspath(extract_dir)))
        final_dir = os.path.realpath(os.path.abspath(extract_dir))
        current_dir = os.path.realpath(os.path.abspath(current_bundle_dir)) if current_bundle_dir else ''

        if os.path.isdir(final_dir):
            if self._is_extracted_bundle_usable(final_dir):
                return final_dir

            if self._same_real_path(final_dir, current_dir):
                raise RuntimeError(f'Refuse to remove current running bundle directory: {final_dir}')

            shutil.rmtree(final_dir)

        temp_dir = tempfile.mkdtemp(
            prefix=f'{os.path.basename(final_dir)}.extracting.',
            dir=release_dir,
        )

        try:
            safe_extract_zip_archive(archive_path, temp_dir)

            rchclient_path = os.path.join(temp_dir, 'rchclient.py')
            if not os.path.isfile(rchclient_path):
                raise FileNotFoundError(f'rchclient.py not found after extract: {rchclient_path}')

            # 发布前再检查一次，兼容两个 update 几乎同时解同一个 bundle 的情况。
            if os.path.isdir(final_dir):
                if self._is_extracted_bundle_usable(final_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return final_dir

                if self._same_real_path(final_dir, current_dir):
                    raise RuntimeError(f'Refuse to replace current running bundle directory: {final_dir}')

                shutil.rmtree(final_dir)

            os.replace(temp_dir, final_dir)
            return final_dir

        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    @desc('Build, download, extract and launch the latest client bundle', group='session')
    @interruptible()
    def update(self, arg=''):
        try:
            self._send_info('Bundle building requested', 0)
            bundle_meta = self._request_update_bundle()
            self._send_success('Bundle building completed', 0)

            release_dir = get_client_bundle_release_dir()
            archive_path = os.path.join(release_dir, bundle_meta['file_name'])
            extract_dir = build_bundle_extract_dir(release_dir, bundle_meta['file_name'])

            self._send_info(f'Bundle downloading: {bundle_meta['file_name']}', 0)
            self._download_bundle_archive(bundle_meta['download_url'], archive_path)
            self._send_success(f'Bundled downloaded successfully: {archive_path}', 0)

            current_bundle_dir = self._get_current_bundle_release_dir(release_dir)

            self._send_info(f'Bundle extracting...', 0)
            extract_dir = self._extract_update_bundle_safely(
                archive_path,
                extract_dir,
                current_bundle_dir,
            )
            self._send_success(f'Bundle ready at {extract_dir}')

            rchclient_path = os.path.join(extract_dir, 'rchclient.py')
            self._send_info(f'Preparing to launch script: {rchclient_path}', 0)


            # if os.path.isdir(extract_dir):
            #     shutil.rmtree(extract_dir)
            #
            # self._send_info(f'Bundle extracting...', 0)
            # safe_extract_zip_archive(archive_path, extract_dir)
            # self._send_success(f'Bundle extracted to {extract_dir}')
            #
            # rchclient_path = os.path.join(extract_dir, 'rchclient.py')
            # if not os.path.isfile(rchclient_path):
            #     raise FileNotFoundError(f'rchclient.py not found after extract: {rchclient_path}')
            #
            # self._send_info(f'Preparing to launch script: {rchclient_path}', 0)

            if detect_platform_alias() == 'ios':
                self._send_success(f'iOS detected, please restart Pythonista app and manually run script: {rchclient_path}', eof=1)


            else:
                process = spawn_detached_python_script(rchclient_path, cwd=extract_dir)
                self._send_success(f'Script launched successfully, PID: {process.pid}', eof=1)
        except Exception as e:
            self._send_error(f'Failed to update client bundle: {e}', eof=1)

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
                self._send_warning(f'Skipped: current client is not running from default bundle releases directory', 0)
                self._send_warning(f'Default Release Dir: {release_dir}', 1)
                return

            result = self._clean_outdated_bundle_releases(release_dir, current_bundle_dir)
            return 1, self._format_clean_outdated_releases_result(result)
        except Exception as e:
            return self._send_error(f'Failed to clean outdated releases: {e}', 1)
