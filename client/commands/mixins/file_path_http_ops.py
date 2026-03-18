import json
import os

import requests

from client.config.config import UPLOAD_BASE_URL
from core.utils.decorator import desc


class CommandFilePathHttpMixin:
    """
    HTTP 版路径命令 mixin。

    说明：
    - 保持命令名与旧版 file_path_ops 一致，方便切换
    - 旧版 file_path_ops.py 不改、不删
    - 当前主要把 download_path 改为通过 server Flask HTTP 上传
    - 其他路径类命令仍然是本地文件操作，只是保留同样的对外命令名
    """

    def _upload_file_to_server_via_http(self, file_path: str, category: str = 'remote_downloads'):
        """
        将指定文件通过 HTTP 上传到 server Flask
        """
        upload_url = UPLOAD_BASE_URL + '/api/files/upload'
        client_id = getattr(self.socket, 'client_id', '') or ''

        with open(file_path, 'rb') as file_obj:
            response = requests.post(
                upload_url,
                files={'file': (os.path.basename(file_path), file_obj)},
                data={
                    'category': category,
                    'client_id': client_id,
                },
                timeout=60,
            )

        return response

    @desc('Download a file by path', group='file_path', suggest=False)
    def download_path(self, path=''):
        """
        按路径“下载”文件：
        HTTP 版实现为 client 直接上传到 server Flask。
        """
        try:
            file_path = self._require_existing_file_from_arg(path)
            file_size = os.path.getsize(file_path)

            self._send_interim_result(1, f'Preparing HTTP upload: {file_path}', 0)
            self._send_interim_result(1, f'File size: {file_size} bytes', 0)

            response = self._upload_file_to_server_via_http(file_path)
            response.raise_for_status()

            try:
                payload = response.json()
            except Exception:
                payload = None

            if isinstance(payload, dict):
                message = payload.get('message') or 'HTTP upload completed'
                data = payload.get('data') or {}
                stored_name = data.get('stored_name') or ''
                original_name = data.get('original_name') or os.path.basename(file_path)

                if stored_name:
                    return 1, (
                        f'{message}\n'
                        f'Original: {original_name}\n'
                        f'Stored: {stored_name}'
                    )

                return 1, message

            return 1, 'HTTP upload completed'
        except Exception as e:
            return 0, f'Failed to download file via HTTP: {e}'

    @desc('Browse directory as JSON payload', group='file_path', suggest=False)
    def browse_dir(self, path=''):
        """
        浏览目录，返回 JSON 结构，供 Web 端可视化文件浏览使用。
        这里仍是本地路径操作；当前架构下不涉及文件字节传输。
        """
        try:
            directory = self._require_existing_directory_from_arg(path)

            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
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
        except Exception as e:
            return 0, f'Failed to browse directory: {e}'

    @desc('Delete a file or directory', group='file_path', suggest=False)
    def delete_path(self, path=''):
        """
        删除文件或目录。
        """
        try:
            target_path = self._require_existing_path_from_arg(path)
            return self._delete_target_path(target_path)
        except Exception as e:
            return 0, f'Failed to delete path: {e}'

    @desc('Create a directory', group='file_path', suggest=False)
    def mkdir_path(self, path=''):
        """
        创建目录。
        """
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))
            if not target_path:
                return 0, 'Path is required'

            self._create_directory(target_path)
            return 1, f'Directory created: {target_path}'
        except Exception as e:
            return 0, f'Failed to create directory: {e}'

    @desc('Rename a file or directory', group='file_path', suggest=False)
    def rename_path(self, arg=''):
        """
        重命名文件或目录。
        兼容：
        - 结构化参数：old_path + new_name / new_path
        """
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
        except Exception as e:
            return 0, f'Failed to rename path: {e}'