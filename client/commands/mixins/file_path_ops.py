import json
import os

from core.utils.decorator import desc


class CommandFilePathMixin:
    @desc('Download a file by path', group='file_path', suggest=False)
    def download_path(self, path=''):
        """
        按路径下载文件，供 Web 远程文件浏览使用。
        """
        try:
            file_path = self._require_existing_file_from_arg(path)
            self._send_file_download(file_path)
        except Exception as e:
            return 0, f'Failed to download file: {e}'

    @desc('Download multiple paths as ZIP archive', group='file_path', suggest=False)
    def download_paths(self, arg=''):
        """
        按路径列表打包下载，支持文件和目录混合。
        结构化参数：
        - paths: 路径数组
        - archive_name: 可选，自定义压缩包名称（不带 .zip 也可）
        """
        temp_archive_path = ''
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid download payload'

            raw_paths = payload.get('paths') or []
            archive_name = (payload.get('archive_name') or '').strip()

            if not isinstance(raw_paths, list) or not raw_paths:
                return 0, 'paths is required'

            resolved_paths = self._require_existing_paths_from_list(raw_paths)
            temp_archive_path = self._create_zip_from_paths(resolved_paths, archive_name=archive_name)

            self._send_file_download(temp_archive_path)
        except Exception as e:
            return 0, f'Failed to download paths: {e}'
        finally:
            if temp_archive_path and os.path.isfile(temp_archive_path):
                try:
                    os.remove(temp_archive_path)
                except Exception:
                    pass

    @desc('Browse directory as JSON payload', group='file_path', suggest=False)
    def browse_dir(self, path=''):
        """
        浏览目录，返回 JSON 结构，供 Web 端可视化文件浏览使用。
        """
        try:
            directory = self._require_existing_directory_from_arg(path)

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