import os
import shutil
import sys

import requests

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.interrupts import interruptible
from client.commands.services.http_file_transfer_service import CommandHttpFileTransferService
from client.config.config import UPLOAD_BASE_URL
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
        # source_type: str,
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        return self._get_http_file_transfer_service().build_http_upload_form_data(
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
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
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_file_to_server_via_http(
            file_path,
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
            extra=extra,
        )

    def _upload_single_file_to_server_result(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_single_file_to_server_result(
            file_path,
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
            extra=extra,
        )

    def _upload_paths_as_zip_to_server_result(
        self,
        resolved_paths: list[str],
        *,
        archive_name: str = '',
        artifact_type: str = 'files',
        category: str = 'default',
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        return self._get_http_file_transfer_service().upload_paths_as_zip_to_server_result(
            resolved_paths,
            archive_name=archive_name,
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
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
                category='remote_browser_download',
                # source_type='client_upload',
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
                # source_type='client_upload',
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
                # source_type='client_upload',
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

            try:
                page = int(page)
            except Exception:
                page = 1

            try:
                page_size = int(page_size)
            except Exception:
                page_size = 100

            if isinstance(show_hidden, str):
                show_hidden = show_hidden.strip().lower() in ('1', 'true', 'yes', 'on')
            else:
                show_hidden = bool(show_hidden)

            if page <= 0:
                page = 1
            if page_size <= 0:
                page_size = 100
            if page_size > 500:
                page_size = 500

            all_entries = []
            with os.scandir(directory) as iterator:
                for entry in self._iter_interruptible(iterator):
                    try:
                        all_entries.append(self._build_directory_entry(entry))
                    except Exception:
                        continue

            all_entries.sort(key=lambda item: (not item['is_dir'], item['name'].lower()))

            total_all = len(all_entries)
            total_hidden = sum(1 for item in all_entries if item.get('is_hidden'))

            if show_hidden:
                visible_entries = all_entries
            else:
                visible_entries = [
                    item for item in all_entries
                    if not item.get('is_hidden')
                ]

            total_visible = len(visible_entries)
            total_pages = max((total_visible + page_size - 1) // page_size, 1)

            if page > total_pages:
                page = total_pages

            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            paged_entries = visible_entries[start_index:end_index]

            payload = {
                'current_path': directory,
                'parent_path': self._build_parent_path(directory),
                'entries': paged_entries,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_visible': total_visible,
                    'total_pages': total_pages,
                    'returned': len(paged_entries),
                },
                'summary': {
                    'total_all': total_all,
                    'total_hidden': total_hidden,
                    'show_hidden': show_hidden,
                }
            }
            return 1, __import__('json').dumps(payload, ensure_ascii=False)
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

            resolved_paths = []
            errors = []
            success_count = 0

            for raw_path in paths:
                try:
                    path_str = str(raw_path or '').strip()
                    if not path_str:
                        continue

                    target_path = self._require_existing_path_from_arg(path_str)
                    resolved_paths.append(target_path)
                except Exception as e:
                    errors.append(f'{raw_path}: {e}')

            if not resolved_paths:
                return 0, 'No valid paths to delete'

            for target_path in resolved_paths:
                try:
                    if os.path.isdir(target_path):
                        shutil.rmtree(target_path)
                        success_count += 1
                    else:
                        os.remove(target_path)
                        success_count += 1
                except Exception as e:
                    errors.append(f'{target_path}: {e}')

            result_msg = f'Deleted {success_count} of {len(resolved_paths)} items'
            if errors:
                result_msg += f'\nErrors:\n  ' + '\n  '.join(errors)

            if success_count > 0:
                return 1, result_msg
            return 0, result_msg

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


    def _is_sub_path(self, parent_path: str, target_path: str) -> bool:
        try:
            common = os.path.commonpath([os.path.abspath(parent_path), os.path.abspath(target_path)])
            return common == os.path.abspath(parent_path)
        except Exception:
            return False


    def _copy_or_move_single_path(self, source_path: str, destination_dir: str, operation: str):
        source_abs = os.path.abspath(source_path)
        destination_dir_abs = os.path.abspath(destination_dir)
        target_path = os.path.join(destination_dir_abs, os.path.basename(source_abs))

        if source_abs == target_path:
            raise ValueError(f'Source and target are the same: {source_abs}')

        if os.path.exists(target_path):
            raise FileExistsError(f'Target already exists: {target_path}')

        if os.path.isdir(source_abs) and self._is_sub_path(source_abs, destination_dir_abs):
            raise ValueError(f'Cannot {operation} a directory into itself or its subdirectory: {source_abs}')

        if operation == 'copy':
            if os.path.isdir(source_abs):
                shutil.copytree(source_abs, target_path)
            else:
                shutil.copy2(source_abs, target_path)
        elif operation == 'move':
            shutil.move(source_abs, target_path)
        else:
            raise ValueError(f'Unsupported operation: {operation}')

        return target_path

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
            success_count = 0
            errors = []

            for source_path in resolved_paths:
                try:
                    self._copy_or_move_single_path(source_path, destination_dir, operation)
                    success_count += 1
                except Exception as e:
                    errors.append(f'{source_path}: {e}')

            action_text = 'Pasted'
            if operation == 'move':
                action_text = 'Moved'
            elif operation == 'copy':
                action_text = 'Copied'

            result_msg = f'{action_text} {success_count} of {len(resolved_paths)} items to: {destination_dir}'
            if errors:
                result_msg += '\nErrors:\n  ' + '\n  '.join(errors)

            if success_count > 0:
                return 1, result_msg
            return 0, result_msg
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

            # 验证路径存在且是文件
            target_path = self._require_existing_path_from_arg(file_path)
            if os.path.isdir(target_path):
                return 0, f'Cannot write to directory: {target_path}'

            # 写入文件
            try:
                with open(target_path, 'w', encoding=encoding) as f:
                    f.write(content)
            except UnicodeEncodeError:
                # 如果指定编码失败，尝试 utf-8
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                encoding = 'utf-8'

            file_size = os.path.getsize(target_path)

            return 1, f'File saved successfully\nPath: {target_path}\nSize: {file_size} bytes\nEncoding: {encoding}'

        except CommandCancelledError:
            return 0, 'Command cancelled'
        except CommandTimeoutError:
            return 0, 'Command timed out and was terminated'
        except Exception as e:
            return 0, f'Failed to save file: {e}'








