import os

from client.config.config import UPLOAD_BASE_URL
from core.utils.decorator import desc


class CommandFileCliMixin:
    @desc('Download a file from the client', group='file')
    def download(self, filename):
        """
        旧版为 socket 发送文件。
        现改为 client 直接通过 HTTP 上传到 server artifact 区。
        """
        try:
            file_path = self._require_existing_file_from_arg(filename)
            return self._upload_single_file_to_server_result(
                file_path,
                category='files'
            )
        except Exception as e:
            return 0, f'Failed to download file: {e}'

    @desc('Receive a file from server via HTTP', group='file', suggest=False)
    def receive_http_upload(self, arg=''):
        """
        通过普通命令下发 HTTP 拉取任务，由 client 自己去 server 拉文件并保存到本地。

        结构化参数：
        - relative_url: server 提供的临时下载相对地址
        - url: 兼容旧字段，完整下载地址
        - filename: 保存时使用的文件名
        - save_dir: 目标目录（可空，空则当前工作目录）
        """
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid HTTP upload payload'

            relative_url = str(payload.get('relative_url') or '').strip()
            url = str(payload.get('url') or '').strip()
            filename = str(payload.get('filename') or '').strip()
            save_dir = str(payload.get('save_dir') or '').strip()

            if not url:
                if not relative_url:
                    return 0, 'url or relative_url is required'
                url = UPLOAD_BASE_URL.rstrip('/') + '/' + relative_url.lstrip('/')

            if not filename:
                return 0, 'filename is required'

            target_dir = self._resolve_target_path(save_dir or '.')
            if os.path.exists(target_dir) and not os.path.isdir(target_dir):
                return 0, f'Target path is not a directory: {target_dir}'

            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, os.path.basename(filename))

            self._send_interim_result(1, f'Preparing HTTP download: {url}', 0)

            #这个过程之后才可取消，之前取消不了。手动设置cancelpolicy之后 会提示command notrun因为这时还没有启动cancelpolicy，(我们不能设置 因为方法能不能被取消取决于strategy
            # 所以我们可以考虑方法开始的时候判断一下当前模式 如果strategy是legacy直接拒绝 而不单纯依赖于上传后判断
            #因为上传到临时目录 也很慢 这个过程用户不知道能不能取消
            # 如果不手动设置则默认方法其实可以被取消，但是又取消不掉，类似pyexec import time;time.sleep(3)
            self._download_file_from_http(url, target_path)
            file_size = os.path.getsize(target_path)

            return 1, (
                f'File saved successfully via HTTP\n'
                f'Path: {target_path}\n'
                f'Size: {file_size} bytes'
            )
        except Exception as e:
            return 0, f'Failed to receive file via HTTP: {e}'

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