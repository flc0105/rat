import json
import os
import shutil

from core.utils.decorator import desc


class CommandFileMixin:
    @desc('Download a file from the client')
    def download(self, filename):
        if os.path.isfile(filename):
            file_size = os.path.getsize(filename)
            self.socket.send_result(self.command_id, 1, 'Preparing file transfer...', eof=0)
            self.socket.send_result(self.command_id, 1, f'File size: {file_size} bytes', eof=0)
            self.socket.send_file(self.command_id, filename)
        else:
            return 0, f'File not found: {os.path.abspath(filename)}'

    @desc('Download a file by path')
    def download_path(self, path=''):
        """
        按路径下载文件，供 Web 远程文件浏览使用。
        """
        try:
            file_path = self._resolve_target_path(self._extract_path_arg(path))
            if not os.path.exists(file_path):
                return 0, f'Path not found: {file_path}'
            if not os.path.isfile(file_path):
                return 0, f'Not a file: {file_path}'

            file_size = os.path.getsize(file_path)
            self.socket.send_result(self.command_id, 1, 'Preparing file transfer...', eof=0)
            self.socket.send_result(self.command_id, 1, f'File size: {file_size} bytes', eof=0)
            self.socket.send_file(self.command_id, file_path)
        except Exception as e:
            return 0, f'Failed to download file: {e}'

    @desc('Browse directory as JSON payload')
    def browse_dir(self, path=''):
        """
        浏览目录，返回 JSON 结构，供 Web 端可视化文件浏览使用。
        """
        try:
            directory = self._resolve_target_path(self._extract_path_arg(path))

            if not os.path.exists(directory):
                return 0, f'Directory not found: {directory}'

            if not os.path.isdir(directory):
                return 0, f'Not a directory: {directory}'

            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    try:
                        entries.append(self._build_directory_entry(entry))
                    except Exception:
                        # 某些文件可能无权限读取 stat，跳过即可，避免整个目录浏览失败
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

    @desc('Delete a file or directory')
    def delete_path(self, path=''):
        """
        删除文件或目录。
        """
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))

            if not os.path.exists(target_path):
                return 0, f'Path not found: {target_path}'

            if os.path.isdir(target_path):
                shutil.rmtree(target_path)
                return 1, f'Directory deleted: {target_path}'

            os.remove(target_path)
            return 1, f'File deleted: {target_path}'
        except Exception as e:
            return 0, f'Failed to delete path: {e}'

    @desc('Create a directory')
    def mkdir_path(self, path=''):
        """
        创建目录。
        """
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))
            if not target_path:
                return 0, 'Path is required'

            if os.path.exists(target_path):
                return 0, f'Path already exists: {target_path}'

            os.makedirs(target_path, exist_ok=False)
            return 1, f'Directory created: {target_path}'
        except Exception as e:
            return 0, f'Failed to create directory: {e}'

    @desc('Rename a file or directory')
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

            if not os.path.exists(old_path):
                return 0, f'Path not found: {old_path}'

            if new_path:
                target_path = self._resolve_target_path(new_path)
            else:
                if not new_name:
                    return 0, 'New name is required'
                target_path = os.path.join(os.path.dirname(old_path), new_name)

            if os.path.exists(target_path):
                return 0, f'Target already exists: {target_path}'

            os.rename(old_path, target_path)
            return 1, f'Renamed to: {target_path}'
        except Exception as e:
            return 0, f'Failed to rename path: {e}'

    # ------------------ 压缩文件 ------------------ #
    @desc('Create a ZIP archive')
    def zip(self, dir_name):
        import pathlib
        import tempfile

        try:
            temp_dir = tempfile.mkdtemp()
            directory = self._validate_directory_exists(dir_name)
            archive_name = os.path.basename(directory)
            parent_dir = pathlib.Path(directory).resolve().parent

            archive_path = shutil.make_archive(
                os.path.join(temp_dir, archive_name),
                format='zip',
                root_dir=parent_dir,
                base_dir=os.path.basename(directory)
            )
            return 1, f'Archive created successfully: {archive_path}'
        except Exception as e:
            return 0, f'Failed to create archive: {e}'

    @desc('Extract a ZIP archive')
    def unzip(self, zip_name):
        try:
            archive_path = self._validate_file_exists(zip_name)
            shutil.unpack_archive(archive_path, os.getcwd())
            return 1, f'Archive extracted to: {os.getcwd()}'
        except Exception as e:
            return 0, f'Failed to extract archive: {e}'