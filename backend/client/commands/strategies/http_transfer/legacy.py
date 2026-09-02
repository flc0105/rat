import os

import requests

from client.commands.strategies.http_transfer.base import HttpTransferStrategy
from client.config.runtime_config import (
    HTTP_DOWNLOAD_CONNECT_TIMEOUT,
    HTTP_DOWNLOAD_READ_TIMEOUT,
    HTTP_UPLOAD_TIMEOUT,
)


# 固定下载分块大小，不再作为 runtime_config 暴露。
HTTP_DOWNLOAD_CHUNK_SIZE = 64 * 1024


class LegacyHttpTransferStrategy(HttpTransferStrategy):
    MODE_NAME = 'legacy'

    # TODO 这个方法上传4GB文件会报错
    def upload_file(self, file_path: str, upload_url: str, form_data: dict, progress_callback=None):
        self.configure_context_for_upload()

        with open(file_path, 'rb') as file_obj:
            return requests.post(
                upload_url,
                files={'file': (os.path.basename(file_path), file_obj)},
                data=form_data,
                timeout=self.resolve_http_timeout(HTTP_UPLOAD_TIMEOUT),
            )

    def download_file(self, url: str, target_path: str, progress_callback=None):
        self.configure_context_for_download()

        with requests.get(
                url,
                stream=True,
                timeout=(
                        HTTP_DOWNLOAD_CONNECT_TIMEOUT,
                        HTTP_DOWNLOAD_READ_TIMEOUT,
                ),
        ) as response:
            response.raise_for_status()
            try:
                total_bytes = max(0, int(response.headers.get('Content-Length') or 0))
            except Exception:
                total_bytes = 0
            transferred_bytes = 0

            with open(target_path, 'wb') as file_obj:
                for chunk in response.iter_content(chunk_size=HTTP_DOWNLOAD_CHUNK_SIZE):
                    if not chunk:
                        continue
                    file_obj.write(chunk)
                    transferred_bytes += len(chunk)
                    if callable(progress_callback):
                        progress_callback(transferred_bytes, total_bytes)
