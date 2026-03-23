import json
import os

import requests

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.http_transfer.factory import build_http_transfer_strategy
from client.commands.interrupts import interruptible
from client.config.config import UPLOAD_BASE_URL
from client.config.runtime_config import (
    HTTP_DOWNLOAD_CHUNK_SIZE,
    HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE,
    HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE,
    HTTP_TRANSFER_MODE,
    HTTP_UPLOAD_CHUNK_SIZE,
    HTTP_UPLOAD_TIMEOUT_CANCELABLE, HTTP_DOWNLOAD_CANCEL_UNSUPPORTED_MESSAGE,
)
from core.utils.decorator import desc


class CommandFileWebMixin:
    """
    HTTP 版路径命令 mixin。

    说明：
    - 文件不再通过 socket 传输
    - client 通过 HTTP 上传到 server
    - 上传时显式上报：
      - artifact_type
      - category
      - source_type
      - source_command_id
      以便服务端正确分类并挂回 execution history
    - HTTP 传输支持两种模式：
      - legacy：保留原版 requests files=/iter_content 行为，不支持取消
      - cancelable：支持取消 / timeout / context
    """

    HTTP_TRANSFER_MODE = HTTP_TRANSFER_MODE
    HTTP_UPLOAD_TIMEOUT = HTTP_UPLOAD_TIMEOUT_CANCELABLE
    HTTP_DOWNLOAD_TIMEOUT = (
        HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE,
        HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE,
    )
    HTTP_DOWNLOAD_CHUNK_SIZE = HTTP_DOWNLOAD_CHUNK_SIZE
    HTTP_UPLOAD_CHUNK_SIZE = HTTP_UPLOAD_CHUNK_SIZE

    def _get_http_transfer_strategy(self):
        return build_http_transfer_strategy(self, self.HTTP_TRANSFER_MODE)

    def _build_http_upload_form_data(
        self,
        *,
        artifact_type: str,
        category: str,
        source_type: str,
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        client_id = getattr(self.socket, 'client_id', '') or ''

        payload = {
            'artifact_type': (artifact_type or 'files').strip() or 'files',
            'category': (category or '').strip() or 'default',
            'client_id': client_id,
            'source_type': (source_type or 'client_upload').strip() or 'client_upload',
            'source_command_id': self.command_id if self.command_id is not None else '',
            'related_path': (related_path or '').strip(),
        }

        if isinstance(extra, dict) and extra:
            payload['extra'] = json.dumps(extra, ensure_ascii=False)

        return payload

    def _resolve_http_timeout(self, fallback_timeout=None):
        timeout_value = self._resolve_timeout(fallback_timeout)
        if timeout_value is None:
            return None
        return max(float(timeout_value), 0.001)

    def _parse_http_upload_response(self, response):
        try:
            payload = response.json()
        except Exception:
            payload = None
        return payload

    def _build_http_upload_success_message(self, payload, file_path: str, fallback_message: str):
        if not isinstance(payload, dict):
            return fallback_message

        message = payload.get('message') or fallback_message
        data = payload.get('data') or {}

        original_name = data.get('original_name') or os.path.basename(file_path)
        stored_name = data.get('stored_name') or ''
        artifact_id = data.get('artifact_id') or ''
        download_url = data.get('download_url') or ''

        lines = [message, f'Original: {original_name}']
        if stored_name:
            lines.append(f'Stored: {stored_name}')
        if artifact_id:
            lines.append(f'Artifact ID: {artifact_id}')
        if download_url:
            lines.append(f'Download URL: {download_url}')

        return '\n'.join(lines)

    def _upload_file_to_server_via_http(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        upload_url = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'
        form_data = self._build_http_upload_form_data(
            artifact_type=artifact_type,
            category=category,
            source_type=source_type,
            related_path=related_path,
            extra=extra,
        )

        strategy = self._get_http_transfer_strategy()
        return strategy.upload_file(file_path, upload_url, form_data)

    def _upload_single_file_to_server_result(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        file_size = os.path.getsize(file_path)

        self._send_interim_result(1, f'Preparing HTTP upload: {file_path}', 0)
        self._send_interim_result(1, f'File size: {file_size} bytes', 0)

        response = self._upload_file_to_server_via_http(
            file_path,
            artifact_type=artifact_type,
            category=category,
            source_type=source_type,
            related_path=related_path,
            extra=extra,
        )
        response.raise_for_status()

        payload = self._parse_http_upload_response(response)
        message = self._build_http_upload_success_message(
            payload,
            file_path=file_path,
            fallback_message='HTTP upload completed'
        )
        return 1, message

    def _upload_paths_as_zip_to_server_result(
        self,
        resolved_paths: list[str],
        *,
        archive_name: str = '',
        artifact_type: str = 'files',
        category: str = 'default',
        source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        temp_archive_path = ''
        try:
            temp_archive_path = self._create_zip_from_paths(
                resolved_paths,
                archive_name=archive_name
            )
            return self._upload_single_file_to_server_result(
                temp_archive_path,
                artifact_type=artifact_type,
                category=category,
                source_type=source_type,
                related_path=related_path,
                extra=extra,
            )
        finally:
            if temp_archive_path and os.path.isfile(temp_archive_path):
                try:
                    os.remove(temp_archive_path)
                except Exception:
                    pass

    def _download_file_from_http(self, url: str, target_path: str):
        strategy = self._get_http_transfer_strategy()
        return strategy.download_file(url, target_path)

    @desc('Download a file by path', group='file_path', suggest=False)
    @interruptible()
    def download_path(self, path=''):
        """
        下载单个路径到 server artifact files 区
        """
        try:
            if HTTP_TRANSFER_MODE == 'legacy':
                self._set_cancel_policy(
                    supported=False,
                    message=HTTP_DOWNLOAD_CANCEL_UNSUPPORTED_MESSAGE)

            file_path = self._require_existing_file_from_arg(path)
            return self._upload_single_file_to_server_result(
                file_path,
                artifact_type='files',
                category='remote_browser_download',
                source_type='client_upload',
                related_path=file_path,
            )
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except (CommandTimeoutError, requests.Timeout):
            return 0, 'HTTP upload timed out'
        except Exception as e:
            return 0, f'Failed to download file via HTTP: {e}'

    @desc('Download multiple paths as ZIP archive', group='file_path', suggest=False)
    @interruptible()
    def download_paths(self, arg=''):
        """
        按路径列表打包上传到 server artifact files 区
        """
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid download payload'

            raw_paths = payload.get('paths') or []
            archive_name = (payload.get('archive_name') or '').strip()

            if not isinstance(raw_paths, list) or not raw_paths:
                return 0, 'paths is required'

            resolved_paths = self._require_existing_paths_from_list(raw_paths)
            related_path = '\n'.join(resolved_paths)

            return self._upload_paths_as_zip_to_server_result(
                resolved_paths,
                archive_name=archive_name,
                artifact_type='files',
                category='remote_browser_bundle',
                source_type='client_upload',
                related_path=related_path,
            )
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except (CommandTimeoutError, requests.Timeout):
            return 0, 'HTTP upload timed out'
        except Exception as e:
            return 0, f'Failed to download paths via HTTP: {e}'

    @desc('Preview a file by path', group='file_path', suggest=False)
    @interruptible()
    def preview_path(self, path=''):
        """
        拉取预览文件到 server artifact previews 区
        """
        try:
            file_path = self._require_existing_file_from_arg(path)
            return self._upload_single_file_to_server_result(
                file_path,
                artifact_type='previews',
                category='preview_cache',
                source_type='client_upload',
                related_path=file_path,
            )
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except (CommandTimeoutError, requests.Timeout):
            return 0, 'HTTP upload timed out'
        except Exception as e:
            return 0, f'Failed to preview file via HTTP: {e}'

    @desc('Browse directory as JSON payload', group='file_path', suggest=False)
    @interruptible()
    def browse_dir(self, path=''):
        try:
            directory = self._require_existing_directory_from_arg(path)

            entries = []
            with os.scandir(directory) as iterator:
                for entry in self._iter_interruptible(iterator):
                    try:
                        entries.append(self._build_directory_entry(entry))
                    except Exception:
                        continue

            entries.sort(key=lambda item: (not item['is_dir'], item['name'].lower()))

            payload = {
                'current_path': directory,
                'parent_path': self._build_parent_path(directory),
                'entries': entries
            }
            return 1, json.dumps(payload, ensure_ascii=False)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to browse directory: {e}'

    @desc('Delete a file or directory', group='file_path', suggest=False)
    @interruptible()
    def delete_path(self, path=''):
        try:
            target_path = self._require_existing_path_from_arg(path)
            return self._delete_target_path(target_path)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to delete path: {e}'

    @desc('Create a directory', group='file_path', suggest=False)
    @interruptible()
    def mkdir_path(self, path=''):
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))
            if not target_path:
                return 0, 'Path is required'

            self._create_directory(target_path)
            return 1, f'Directory created: {target_path}'
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to create directory: {e}'

    @desc('Rename a file or directory', group='file_path', suggest=False)
    @interruptible()
    def rename_path(self, arg=''):
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid rename payload'

            old_path = self._resolve_target_path(payload.get('old_path', ''))
            new_name = (payload.get('new_name') or '').strip()
            new_path = (payload.get('new_path') or '').strip()

            renamed_path = self._rename_target_path(
                old_path=old_path,
                new_name=new_name,
                new_path=new_path
            )
            return 1, f'Renamed to: {renamed_path}'
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to rename path: {e}'
