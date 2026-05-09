import os

import requests

from client.commands.strategies.http_transfer.base import HttpTransferStrategy
from client.config.runtime_config import (
    HTTP_DOWNLOAD_CHUNK_SIZE,
    HTTP_DOWNLOAD_CONNECT_TIMEOUT_LEGACY,
    HTTP_DOWNLOAD_READ_TIMEOUT_LEGACY,
    HTTP_UPLOAD_TIMEOUT_LEGACY,
)


class LegacyHttpTransferStrategy(HttpTransferStrategy):
    MODE_NAME = 'legacy'

    # TODO 这个方法上传4GB文件会报错
    def upload_file(self, file_path: str, upload_url: str, form_data: dict):
        self.configure_context_for_upload()

        with open(file_path, 'rb') as file_obj:
            return requests.post(
                upload_url,
                files={'file': (os.path.basename(file_path), file_obj)},
                data=form_data,
                timeout=self.resolve_http_timeout(HTTP_UPLOAD_TIMEOUT_LEGACY),
            )

    def download_file(self, url: str, target_path: str):
        self.configure_context_for_download()

        with requests.get(
                url,
                stream=True,
                timeout=(
                        HTTP_DOWNLOAD_CONNECT_TIMEOUT_LEGACY,
                        HTTP_DOWNLOAD_READ_TIMEOUT_LEGACY,
                ),
        ) as response:
            response.raise_for_status()
            with open(target_path, 'wb') as file_obj:
                for chunk in response.iter_content(chunk_size=HTTP_DOWNLOAD_CHUNK_SIZE):
                    if not chunk:
                        continue
                    file_obj.write(chunk)