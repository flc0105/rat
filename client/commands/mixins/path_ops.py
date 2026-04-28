from client.commands.services.archive_service import ArchiveService
from client.commands.services.file_system_service import FileSystemService
from client.commands.services.path_resolver import PathResolver
from client.commands.services.structured_arg_codec import StructuredArgCodec


class CommandPathMixin:
    def __init__(self, *args, **kwargs):
        self._structured_arg_codec = None
        self._path_resolver = None
        self._file_system_service = None
        self._archive_service = None
        super().__init__(*args, **kwargs)

    def _get_structured_arg_codec(self):
        if self._structured_arg_codec is None:
            self._structured_arg_codec = StructuredArgCodec()
        return self._structured_arg_codec

    def _get_path_resolver(self):
        if self._path_resolver is None:
            self._path_resolver = PathResolver(
                codec=self._get_structured_arg_codec(),
                iter_interruptible=self._iter_interruptible,
            )
        return self._path_resolver

    def _get_file_system_service(self):
        if self._file_system_service is None:
            self._file_system_service = FileSystemService(
                path_resolver=self._get_path_resolver(),
                run_interruptible=self._run_interruptible,
                iter_interruptible=self._iter_interruptible,
            )
        return self._file_system_service

    def _get_archive_service(self):
        if self._archive_service is None:
            self._archive_service = ArchiveService(
                path_resolver=self._get_path_resolver(),
                ensure_not_interrupted=self._ensure_not_interrupted,
                iter_interruptible=self._iter_interruptible,
            )
        return self._archive_service

    def _validate_directory_exists(self, path):
        return self._get_path_resolver().validate_directory_exists(path)

    def _validate_file_exists(self, path):
        return self._get_path_resolver().validate_file_exists(path)

    def _resolve_target_path(self, path: str) -> str:
        return self._get_path_resolver().resolve_target_path(path)

    def _build_parent_path(self, path: str):
        return self._get_path_resolver().build_parent_path(path)

    def _build_directory_entry(self, entry):
        return self._get_file_system_service().build_directory_entry(entry)

    def _is_hidden_entry(self, entry, stat_result):
        return self._get_file_system_service().is_hidden_entry(entry, stat_result)

    def _strip_wrapped_quotes(self, value: str) -> str:
        return self._get_structured_arg_codec().strip_wrapped_quotes(value)

    def _decode_structured_arg(self, raw):
        return self._get_structured_arg_codec().decode(raw)

    def _extract_path_arg(self, raw) -> str:
        return self._get_structured_arg_codec().extract_path(raw)

    def _to_abs_path(self, path: str) -> str:
        return self._get_path_resolver().to_abs_path(path)

    def _is_file_path(self, path: str) -> bool:
        return self._get_path_resolver().is_file_path(path)

    def _get_current_directory(self) -> str:
        return self._get_path_resolver().get_current_directory()

    def _require_existing_path_from_arg(self, raw) -> str:
        return self._get_path_resolver().require_existing_path_from_arg(raw)

    def _require_existing_file_from_arg(self, raw) -> str:
        return self._get_path_resolver().require_existing_file_from_arg(raw)

    def _require_existing_directory_from_arg(self, raw) -> str:
        return self._get_path_resolver().require_existing_directory_from_arg(raw)

    def _require_existing_paths_from_list(self, paths) -> list[str]:
        return self._get_path_resolver().require_existing_paths_from_list(paths)

    def _delete_target_path(self, target_path: str):
        return self._get_file_system_service().delete_target_path(target_path)

    def _create_directory(self, target_path: str):
        return self._get_file_system_service().create_directory(target_path)

    def _rename_target_path(self, old_path: str, new_name: str = '', new_path: str = '') -> str:
        return self._get_file_system_service().rename_target_path(
            old_path=old_path,
            new_name=new_name,
            new_path=new_path,
        )

    def _create_zip_archive(self, dir_name: str) -> str:
        return self._get_archive_service().create_zip_archive(dir_name)

    def _build_download_archive_name(self, paths: list[str], archive_name: str = '') -> str:
        return self._get_archive_service().build_download_archive_name(paths, archive_name=archive_name)

    def _iter_directory_files(self, directory: str):
        return self._get_archive_service().iter_directory_files(directory)

    def _write_path_to_zip(self, archive, path: str, used_names: set[str]):
        return self._get_archive_service().write_path_to_zip(archive, path, used_names)

    def _create_zip_from_paths(self, paths: list[str], archive_name: str = '') -> str:
        return self._get_archive_service().create_zip_from_paths(paths, archive_name=archive_name)

    def _extract_archive_to_cwd(self, archive_path: str):
        return self._get_archive_service().extract_archive_to_cwd(archive_path)