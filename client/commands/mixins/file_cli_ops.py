from core.utils.decorator import desc


class CommandFileCliMixin:
    @desc('Download a file from the client', group='file')
    def download(self, filename):
        if self._is_file_path(filename):
            self._send_file_download(filename)
        else:
            return 0, f'File not found: {self._to_abs_path(filename)}'

    @desc('Create a ZIP archive', group='file')
    def zip(self, dir_name):
        """
        按命令行参数压缩目录。
        """
        try:
            archive_path = self._create_zip_archive(dir_name)
            return 1, f'Archive created successfully: {archive_path}'
        except Exception as e:
            return 0, f'Failed to create archive: {e}'

    @desc('Extract a ZIP archive', group='file')
    def unzip(self, zip_name):
        """
        按命令行参数解压压缩包到当前工作目录。
        """
        try:
            archive_path = self._validate_file_exists(zip_name)
            self._extract_archive_to_cwd(archive_path)
            return 1, f'Archive extracted to: {self._get_current_directory()}'
        except Exception as e:
            return 0, f'Failed to extract archive: {e}'