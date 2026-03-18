import base64
import json
import os
import shutil
import stat as stat_module
import tempfile
import time
import zipfile


class CommandPathMixin:
    def _validate_directory_exists(self, path):
        """
        校验目录是否存在，并返回绝对路径
        """
        directory = os.path.abspath(path)
        if not os.path.isdir(directory):
            raise FileNotFoundError(f'Directory not found: {directory}')
        return directory

    def _validate_file_exists(self, path):
        """
        校验文件是否存在，并返回绝对路径
        """
        file_path = os.path.abspath(path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f'File not found: {file_path}')
        return file_path

    def _resolve_target_path(self, path: str) -> str:
        """
        将传入路径解析为当前客户端上的绝对路径
        - 空路径默认当前工作目录
        - 相对路径基于当前 cwd
        """
        raw_path = (path or '').strip()
        if not raw_path:
            raw_path = '.'

        if os.path.isabs(raw_path):
            return os.path.abspath(raw_path)

        return os.path.abspath(os.path.join(os.getcwd(), raw_path))

    def _build_parent_path(self, path: str):
        """
        获取上级目录；如果已经到根目录，则返回 None
        """
        current = os.path.abspath(path)
        parent = os.path.dirname(current)
        if parent == current:
            return None
        return parent

    def _build_directory_entry(self, entry):
        """
        构造目录项描述
        """
        stat_result = entry.stat(follow_symlinks=False)
        is_dir = entry.is_dir(follow_symlinks=True)
        is_symlink = entry.is_symlink()
        is_hidden = self._is_hidden_entry(entry, stat_result)

        return {
            'name': entry.name,
            'path': os.path.abspath(entry.path),
            'is_dir': is_dir,
            'is_symlink': is_symlink,
            'is_hidden': is_hidden,
            'size': 0 if is_dir else stat_result.st_size,
            'modified_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_result.st_mtime))
        }

    def _is_hidden_entry(self, entry, stat_result):
        """
        判断目录项是否为隐藏文件
        - Unix/macOS: 以 . 开头
        - Windows: 支持文件属性隐藏位
        """
        if entry.name.startswith('.'):
            return True

        if os.name == 'nt':
            file_attrs = getattr(stat_result, 'st_file_attributes', 0)
            if file_attrs & getattr(stat_module, 'FILE_ATTRIBUTE_HIDDEN', 0):
                return True

        return False

    def _strip_wrapped_quotes(self, value: str) -> str:
        """
        去掉参数最外层成对引号
        """
        text = (value or '').strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            return text[1:-1]
        return text

    def _decode_structured_arg(self, raw):
        """
        解码结构化参数：
        - __json__:<base64(json)>
        - 普通字符串
        """
        text = self._strip_wrapped_quotes(raw)
        if not text:
            return ''

        prefix = '__json__:'
        if text.startswith(prefix):
            encoded = text[len(prefix):]
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode('utf-8')
            return json.loads(decoded)

        return text

    def _extract_path_arg(self, raw) -> str:
        """
        提取路径参数，兼容普通字符串和结构化参数
        """
        value = self._decode_structured_arg(raw)
        if isinstance(value, dict):
            return (value.get('path') or '').strip()
        return (value or '').strip()

    # ------------------ 共用 helper ------------------ #
    def _to_abs_path(self, path: str) -> str:
        """
        转为绝对路径
        """
        return os.path.abspath(path)

    def _is_file_path(self, path: str) -> bool:
        """
        判断是否为现有文件
        """
        return os.path.isfile(path)

    def _get_current_directory(self) -> str:
        """
        获取当前工作目录
        """
        return os.getcwd()

    def _send_file_download(self, file_path: str):
        """
        发送文件下载（共用底层逻辑）
        """
        file_size = os.path.getsize(file_path)
        self.socket.send_result(self.command_id, 1, 'Preparing file transfer...', eof=0)
        self.socket.send_result(self.command_id, 1, f'File size: {file_size} bytes', eof=0)
        self.socket.send_file(self.command_id, file_path)

    def _require_existing_path_from_arg(self, raw) -> str:
        """
        从结构化/普通参数中提取并校验路径存在
        """
        target_path = self._resolve_target_path(self._extract_path_arg(raw))
        if not os.path.exists(target_path):
            raise FileNotFoundError(f'Path not found: {target_path}')
        return target_path

    def _require_existing_file_from_arg(self, raw) -> str:
        """
        从结构化/普通参数中提取并校验文件存在
        """
        file_path = self._require_existing_path_from_arg(raw)
        if not os.path.isfile(file_path):
            raise IsADirectoryError(f'Not a file: {file_path}')
        return file_path

    def _require_existing_directory_from_arg(self, raw) -> str:
        """
        从结构化/普通参数中提取并校验目录存在
        """
        directory = self._resolve_target_path(self._extract_path_arg(raw))
        if not os.path.exists(directory):
            raise FileNotFoundError(f'Directory not found: {directory}')
        if not os.path.isdir(directory):
            raise NotADirectoryError(f'Not a directory: {directory}')
        return directory

    def _require_existing_paths_from_list(self, paths) -> list[str]:
        """
        从路径列表中提取并校验所有路径存在
        """
        resolved_paths = []

        for item in paths:
            raw_path = ''
            if isinstance(item, dict):
                raw_path = (item.get('path') or '').strip()
            else:
                raw_path = str(item or '').strip()

            if not raw_path:
                continue

            target_path = self._resolve_target_path(raw_path)
            if not os.path.exists(target_path):
                raise FileNotFoundError(f'Path not found: {target_path}')

            resolved_paths.append(target_path)

        if not resolved_paths:
            raise ValueError('No valid paths provided')

        return resolved_paths

    def _delete_target_path(self, target_path: str):
        """
        删除文件或目录
        """
        if os.path.isdir(target_path):
            shutil.rmtree(target_path)
            return 1, f'Directory deleted: {target_path}'

        os.remove(target_path)
        return 1, f'File deleted: {target_path}'

    def _create_directory(self, target_path: str):
        """
        创建目录
        """
        if os.path.exists(target_path):
            raise FileExistsError(f'Path already exists: {target_path}')

        os.makedirs(target_path, exist_ok=False)

    def _rename_target_path(self, old_path: str, new_name: str = '', new_path: str = '') -> str:
        """
        重命名文件或目录
        """
        if not os.path.exists(old_path):
            raise FileNotFoundError(f'Path not found: {old_path}')

        if new_path:
            target_path = self._resolve_target_path(new_path)
        else:
            if not new_name:
                raise ValueError('New name is required')
            target_path = os.path.join(os.path.dirname(old_path), new_name)

        if os.path.exists(target_path):
            raise FileExistsError(f'Target already exists: {target_path}')

        os.rename(old_path, target_path)
        return target_path

    def _create_zip_archive(self, dir_name: str) -> str:
        """
        创建 ZIP 压缩包并返回压缩包路径
        """
        import pathlib

        temp_dir = tempfile.mkdtemp()
        directory = self._validate_directory_exists(dir_name)
        archive_name = os.path.basename(directory)
        parent_dir = pathlib.Path(directory).resolve().parent

        return shutil.make_archive(
            os.path.join(temp_dir, archive_name),
            format='zip',
            root_dir=parent_dir,
            base_dir=os.path.basename(directory)
        )

    def _build_download_archive_name(self, paths: list[str], archive_name: str = '') -> str:
        """
        生成下载压缩包文件名
        """
        custom_name = (archive_name or '').strip()
        if custom_name:
            if not custom_name.lower().endswith('.zip'):
                custom_name += '.zip'
            return custom_name

        if len(paths) == 1:
            base_name = os.path.basename(paths[0].rstrip('/\\')) or 'download'
            return f'{base_name}.zip'

        timestamp = time.strftime('%Y%m%d-%H%M%S')
        return f'bundle_{timestamp}.zip'

    def _iter_directory_files(self, directory: str):
        """
        遍历目录内所有文件（递归）
        """
        for root, _, files in os.walk(directory):
            for filename in files:
                yield os.path.join(root, filename)

    def _write_path_to_zip(self, archive: zipfile.ZipFile, path: str, used_names: set[str]):
        """
        将单个文件或目录写入 zip，避免顶层重名冲突
        """
        normalized_path = os.path.abspath(path)
        top_name = os.path.basename(normalized_path.rstrip('/\\')) or 'item'
        archive_root = top_name
        suffix_index = 1

        while archive_root in used_names:
            archive_root = f'{top_name}_{suffix_index}'
            suffix_index += 1

        used_names.add(archive_root)

        if os.path.isfile(normalized_path):
            archive.write(normalized_path, arcname=archive_root)
            return

        if os.path.isdir(normalized_path):
            has_content = False

            for file_path in self._iter_directory_files(normalized_path):
                has_content = True
                relative_path = os.path.relpath(file_path, normalized_path)
                archive.write(file_path, arcname=os.path.join(archive_root, relative_path))

            if not has_content:
                directory_entry = archive_root.rstrip('/\\') + '/'
                archive.writestr(directory_entry, '')
            return

        raise FileNotFoundError(f'Path not found: {normalized_path}')

    def _create_zip_from_paths(self, paths: list[str], archive_name: str = '') -> str:
        """
        将多个文件/目录打包到 tempfile 生成的 zip 中
        """
        final_name = self._build_download_archive_name(paths, archive_name=archive_name)
        temp_dir = tempfile.mkdtemp()
        archive_path = os.path.join(temp_dir, final_name)

        used_names = set()
        with zipfile.ZipFile(archive_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in paths:
                self._write_path_to_zip(archive, path, used_names)

        return archive_path

    def _extract_archive_to_cwd(self, archive_path: str):
        """
        解压压缩包到当前工作目录
        """
        shutil.unpack_archive(archive_path, os.getcwd())