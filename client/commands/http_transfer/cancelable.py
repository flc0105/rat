import os
import uuid

import requests

from client.commands.command_context import CommandCancelledError, CommandTimeoutError
from client.commands.http_transfer.base import HttpTransferStrategy
from client.config.runtime_config import (
    HTTP_DOWNLOAD_CHUNK_SIZE,
    HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE,
    HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE,
    HTTP_UPLOAD_CHUNK_SIZE,
    HTTP_UPLOAD_TIMEOUT_CANCELABLE,
)


class CancelableMultipartUploadStream:
    """
    可取消的 multipart/form-data 流。
    """

    def __init__(self, owner, file_path: str, form_data: dict, chunk_size: int = HTTP_UPLOAD_CHUNK_SIZE):
        self.owner = owner
        self.file_path = file_path
        self.form_data = form_data or {}
        self.chunk_size = max(int(chunk_size or HTTP_UPLOAD_CHUNK_SIZE), 1)
        self.boundary = f'----ratboundary{uuid.uuid4().hex}'
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)

        self._opened_file = None
        self._prefix = self._build_prefix_bytes()
        self._suffix = self._build_suffix_bytes()
        self._prefix_offset = 0
        self._suffix_offset = 0
        self._file_finished = False

    def _build_prefix_bytes(self) -> bytes:
        lines = []

        for key, value in self.form_data.items():
            lines.append(f'--{self.boundary}\r\n'.encode('utf-8'))
            lines.append(
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode('utf-8')
            )
            lines.append(str(value).encode('utf-8'))
            lines.append(b'\r\n')

        lines.append(f'--{self.boundary}\r\n'.encode('utf-8'))
        lines.append(
            (
                'Content-Disposition: form-data; '
                f'name="file"; filename="{self.file_name}"\r\n'
            ).encode('utf-8')
        )
        lines.append(b'Content-Type: application/octet-stream\r\n\r\n')
        return b''.join(lines)

    def _build_suffix_bytes(self) -> bytes:
        return f'\r\n--{self.boundary}--\r\n'.encode('utf-8')

    @property
    def content_type(self) -> str:
        return f'multipart/form-data; boundary={self.boundary}'

    @property
    def content_length(self) -> int:
        return len(self._prefix) + self.file_size + len(self._suffix)

    def __len__(self) -> int:
        return self.content_length

    def close(self):
        try:
            if self._opened_file is not None:
                self._opened_file.close()
        except Exception:
            pass
        finally:
            self._opened_file = None

    def _open_file_if_needed(self):
        if self._opened_file is None and not self._file_finished:
            self._opened_file = open(self.file_path, 'rb')

    def _read_from_prefix(self, size: int) -> bytes:
        if self._prefix_offset >= len(self._prefix):
            return b''

        end = min(self._prefix_offset + size, len(self._prefix))
        data = self._prefix[self._prefix_offset:end]
        self._prefix_offset = end
        return data

    def _read_from_file(self, size: int) -> bytes:
        if self._file_finished:
            return b''

        self._open_file_if_needed()
        data = self.owner._read_interruptible(self._opened_file, size)
        if data:
            return data

        self._file_finished = True
        self.close()
        return b''

    def _read_from_suffix(self, size: int) -> bytes:
        if self._suffix_offset >= len(self._suffix):
            return b''

        end = min(self._suffix_offset + size, len(self._suffix))
        data = self._suffix[self._suffix_offset:end]
        self._suffix_offset = end
        return data

    def read(self, size: int = -1) -> bytes:
        self.owner._ensure_not_interrupted()

        if size is None or size < 0:
            size = self.chunk_size

        if size == 0:
            return b''

        parts = []
        remaining = size

        while remaining > 0:
            self.owner._ensure_not_interrupted()

            chunk = self._read_from_prefix(remaining)
            if not chunk:
                chunk = self._read_from_file(remaining)
            if not chunk:
                chunk = self._read_from_suffix(remaining)
            if not chunk:
                break

            parts.append(chunk)
            remaining -= len(chunk)

        return b''.join(parts)


class CancelableHttpTransferStrategy(HttpTransferStrategy):
    MODE_NAME = 'cancelable'

    def is_cancel_supported(self) -> bool:
        return True

    def _create_session(self):
        session = requests.Session()
        self.owner._register_cancel_handler(lambda: session.close())
        self.owner._register_cleanup_handler(lambda: session.close())
        return session

    def upload_file(self, file_path: str, upload_url: str, form_data: dict):
        self.configure_context_for_upload()
        self.owner._ensure_not_interrupted()

        session = self._create_session()
        response = None
        stream = CancelableMultipartUploadStream(self.owner, file_path, form_data)
        self.owner._register_cancel_handler(stream.close)
        self.owner._register_cleanup_handler(stream.close)

        try:
            response = session.post(
                upload_url,
                data=stream,
                headers={
                    'Content-Type': stream.content_type,
                    'Content-Length': str(stream.content_length),
                },
                timeout=self.owner._resolve_http_timeout(HTTP_UPLOAD_TIMEOUT_CANCELABLE),
            )
            self.owner._ensure_not_interrupted()
            return response
        except CommandCancelledError:
            raise
        except CommandTimeoutError:
            raise requests.Timeout('HTTP upload timed out')
        except requests.RequestException as e:
            self.owner._ensure_not_interrupted()
            raise e
        finally:
            try:
                stream.close()
            except Exception:
                pass
            try:
                if response is not None:
                    response.close()
            except Exception:
                pass
            session.close()

    def download_file(self, url: str, target_path: str):
        self.configure_context_for_download()
        self.owner._ensure_not_interrupted()

        session = self._create_session()
        response = None
        file_obj = None
        try:
            response = session.get(
                url,
                stream=True,
                timeout=(
                    HTTP_DOWNLOAD_CONNECT_TIMEOUT_CANCELABLE,
                    self.owner._resolve_http_timeout(HTTP_DOWNLOAD_READ_TIMEOUT_CANCELABLE),
                ),
            )
            response.raise_for_status()

            file_obj = open(target_path, 'wb')
            self.owner._register_cleanup_handler(lambda: file_obj.close())
            self.owner._register_cancel_handler(lambda: file_obj.close())

            for chunk in self.owner._iter_interruptible(
                response.iter_content(chunk_size=HTTP_DOWNLOAD_CHUNK_SIZE)
            ):
                if not chunk:
                    continue
                file_obj.write(chunk)

            file_obj.close()
            file_obj = None
        except CommandCancelledError:
            raise
        except CommandTimeoutError:
            raise requests.Timeout('HTTP download timed out')
        except requests.RequestException as e:
            self.owner._ensure_not_interrupted()
            raise e
        finally:
            if file_obj is not None:
                try:
                    file_obj.close()
                except Exception:
                    pass
            try:
                if response is not None:
                    response.close()
            except Exception:
                pass
            session.close()






