import json

import requests

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.interrupts import interruptible
from client.commands.services.http_file_transfer_service import CommandHttpFileTransferService
from client.config.runtime_config import (
    HTTP_DOWNLOAD_CHUNK_SIZE,
    HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE,
    HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE,
    HTTP_TRANSFER_MODE,
    HTTP_UPLOAD_CHUNK_SIZE,
    HTTP_UPLOAD_TIMEOUT_CANCELABLE,
    HTTP_DOWNLOAD_CANCEL_UNSUPPORTED_MESSAGE,
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

    def __init__(self, *args, **kwargs):
        self._http_file_transfer_service = None
        super().__init__(*args, **kwargs)

    def _get_http_file_transfer_service(self):
        if self._http_file_transfer_service is None:
            self._http_file_transfer_service = CommandHttpFileTransferService(self)
        return self._http_file_transfer_service

    def _get_http_transfer_strategy(self):
        return self._get_http_file_transfer_service().get_transfer_strategy()

    def _build_http_upload_form_data(
        self,
        *,
        artifact_type: str,
        category: str,
        extra: dict | None = None,
    ) -> dict:
        return self._get_http_file_transfer_service().build_http_upload_form_data(
            artifact_type=artifact_type,
            category=category,
            extra=extra,
        )

    def _resolve_http_timeout(self, fallback_timeout=None):
        return self._get_http_file_transfer_service().resolve_http_timeout(
            fallback_timeout=fallback_timeout
        )

    def _parse_http_upload_response(self, response):
        return self._get_http_file_transfer_service().parse_http_upload_response(response)

    def _build_http_upload_success_message(self, payload, file_path: str, fallback_message: str):
        return self._get_http_file_transfer_service().build_http_upload_success_message(
            payload,
            file_path=file_path,
            fallback_message=fallback_message,
        )

    def _upload_file_to_server_via_http(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_file_to_server_via_http(
            file_path,
            artifact_type=artifact_type,
            category=category,
            extra=extra,
        )

    def _upload_single_file_to_server_result(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_single_file_to_server_result(
            file_path,
            artifact_type=artifact_type,
            category=category,
            extra=extra,
        )

    def _upload_paths_as_zip_to_server_result(
        self,
        resolved_paths: list[str],
        *,
        archive_name: str = '',
        artifact_type: str = 'files',
        category: str = 'default',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_paths_as_zip_to_server_result(
            resolved_paths,
            archive_name=archive_name,
            artifact_type=artifact_type,
            category=category,
            extra=extra,
        )

    def _download_file_from_http(self, url: str, target_path: str):
        return self._get_http_file_transfer_service().download_file_from_http(
            url,
            target_path
        )

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
                category='download',
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

            return self._upload_paths_as_zip_to_server_result(
                resolved_paths,
                archive_name=archive_name,
                artifact_type='files',
                category='bundle',
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
            payload = self._decode_structured_arg(path)
            if isinstance(payload, dict):
                directory = self._require_existing_directory_from_arg(payload.get('path', ''))
                page = payload.get('page', 1)
                page_size = payload.get('page_size', 100)
                show_hidden = payload.get('show_hidden', False)
            else:
                directory = self._require_existing_directory_from_arg(path)
                page = 1
                page_size = 100
                show_hidden = False

            result_payload = self._get_file_system_service().browse_directory(
                directory,
                page=page,
                page_size=page_size,
                show_hidden=show_hidden,
            )
            return 1, json.dumps(result_payload, ensure_ascii=False)
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

    @desc('Delete multiple files or directories', group='file_path', suggest=False)
    @interruptible()
    def delete_paths(self, arg=''):
        """
        批量删除多个文件或目录
        参数格式: __json__:base64编码的JSON {"paths": ["path1", "path2", ...]}
        """
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid delete payload'

            paths = payload.get('paths')
            if not isinstance(paths, list) or not paths:
                return 0, 'paths is required and must be a non-empty list'

            return self._get_file_system_service().delete_paths(paths)
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to delete paths: {e}'

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

    @desc('Paste copied or moved files into a directory', group='file_path', suggest=False)
    @interruptible()
    def paste_paths(self, arg=''):
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid paste payload'

            raw_paths = payload.get('paths') or []
            destination_dir = self._require_existing_directory_from_arg(payload.get('destination_dir', ''))
            operation = str(payload.get('operation', 'copy') or 'copy').strip().lower()

            if operation not in ('copy', 'move'):
                return 0, 'operation must be copy or move'

            if not isinstance(raw_paths, list) or not raw_paths:
                return 0, 'paths is required and must be a non-empty list'

            resolved_paths = self._require_existing_paths_from_list(raw_paths)
            return self._get_file_system_service().paste_paths(
                resolved_paths,
                destination_dir,
                operation,
            )
        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to paste paths: {e}'

    @desc('Save content to a file', group='file_path', suggest=False)
    @interruptible()
    def save_file_content(self, arg=''):
        """
        保存内容到文件
        参数格式: __json__:base64编码的JSON
        {
            "path": "/path/to/file",
            "content": "file content",
            "encoding": "utf-8"  # 可选，默认 utf-8
        }
        """
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid save payload'

            file_path = payload.get('path', '').strip()
            content = payload.get('content', '')
            encoding = payload.get('encoding', 'utf-8')

            if not file_path:
                return 0, 'path is required'

            target_path, file_size, encoding = self._get_file_system_service().save_file_content(
                file_path,
                content,
                encoding,
            )

            return 1, f'File saved successfully\nPath: {target_path}\nSize: {file_size} bytes\nEncoding: {encoding}'

        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to save file: {e}'