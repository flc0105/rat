import os
import shutil
import tempfile
import time
import zipfile

from client.config.runtime_config import ZIP_CANCEL_CHECK_INTERVAL
from client.commands.common.services.filesystem.path_resolver import PathResolver


class ArchiveService:
    """
    压缩包创建与解压服务。
    """

    def __init__(self, path_resolver: PathResolver, ensure_not_interrupted=None, iter_interruptible=None):
        self.path_resolver = path_resolver
        self.ensure_not_interrupted = ensure_not_interrupted
        self.iter_interruptible = iter_interruptible

    def _ensure_not_interrupted(self):
        if self.ensure_not_interrupted is not None:
            self.ensure_not_interrupted()

    def _iter(self, iterable, check_interval: int = 1):
        if self.iter_interruptible is None:
            return iterable
        return self.iter_interruptible(iterable, check_interval=check_interval)

    def create_zip_archive(self, dir_name: str) -> str:
        import pathlib

        temp_dir = tempfile.mkdtemp()
        directory = self.path_resolver.validate_directory_exists(dir_name)
        archive_name = os.path.basename(directory)
        parent_dir = pathlib.Path(directory).resolve().parent

        return shutil.make_archive(
            os.path.join(temp_dir, archive_name),
            format='zip',
            root_dir=parent_dir,
            base_dir=os.path.basename(directory)
        )

    def build_download_archive_name(self, paths: list[str], archive_name: str = '') -> str:
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

    def iter_directory_files(self, directory: str):
        for root, _, files in self._iter(os.walk(directory), check_interval=ZIP_CANCEL_CHECK_INTERVAL):
            for filename in self._iter(files, check_interval=ZIP_CANCEL_CHECK_INTERVAL):
                yield os.path.join(root, filename)

    def write_path_to_zip(self, archive: zipfile.ZipFile, path: str, used_names: set[str]):
        normalized_path = os.path.abspath(path)
        top_name = os.path.basename(normalized_path.rstrip('/\\')) or 'item'
        archive_root = top_name
        suffix_index = 1

        while archive_root in used_names:
            self._ensure_not_interrupted()
            archive_root = f'{top_name}_{suffix_index}'
            suffix_index += 1

        used_names.add(archive_root)

        if os.path.isfile(normalized_path):
            archive.write(normalized_path, arcname=archive_root)
            return

        if os.path.isdir(normalized_path):
            has_content = False

            for file_path in self.iter_directory_files(normalized_path):
                has_content = True
                relative_path = os.path.relpath(file_path, normalized_path)
                archive.write(file_path, arcname=os.path.join(archive_root, relative_path))

            if not has_content:
                directory_entry = archive_root.rstrip('/\\') + '/'
                archive.writestr(directory_entry, '')
            return

        raise FileNotFoundError(f'Path not found: {normalized_path}')

    def create_zip_from_paths(self, paths: list[str], archive_name: str = '') -> str:
        final_name = self.build_download_archive_name(paths, archive_name=archive_name)
        temp_dir = tempfile.mkdtemp()
        archive_path = os.path.join(temp_dir, final_name)

        used_names = set()
        with zipfile.ZipFile(archive_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in self._iter(paths, check_interval=ZIP_CANCEL_CHECK_INTERVAL):
                self.write_path_to_zip(archive, path, used_names)

        return archive_path

    def extract_archive_to_cwd(self, archive_path: str):
        shutil.unpack_archive(archive_path, os.getcwd())