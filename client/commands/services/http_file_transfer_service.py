import json
import os

from client.commands.http_transfer.factory import build_http_transfer_strategy
from client.config.config import UPLOAD_BASE_URL


class CommandHttpFileTransferService:
    """
    HTTP 文件传输服务。

    职责：
    - 从 CommandFileWebMixin 中抽离 HTTP 上传/下载基础设施
    - 显式承接 HTTP 传输策略、表单构造、响应解析等逻辑
    - 让命令 mixin 只保留“命令入口 + 参数组织”，减少横向隐式耦合
    """

    def __init__(self, owner):
        self.owner = owner

    def get_transfer_strategy(self):
        transfer_mode = getattr(self.owner, 'HTTP_TRANSFER_MODE', '')
        return build_http_transfer_strategy(self.owner, transfer_mode)

    def build_http_upload_form_data(
        self,
        *,
        artifact_type: str,
        category: str,
        # source_type: str,
        related_path: str = '',
        extra: dict | None = None,
    ) -> dict:
        client_id = getattr(self.owner.socket, 'client_id', '') or ''

        payload = {
            'artifact_type': (artifact_type or 'files').strip() or 'files',
            'category': (category or '').strip() or 'default',
            'client_id': client_id,
            # 'source_type': (source_type or 'client_upload').strip() or 'client_upload',
            'source_command_id': self.owner.command_id if self.owner.command_id is not None else '',
            'related_path': (related_path or '').strip(),
        }

        if isinstance(extra, dict) and extra:
            payload['extra'] = json.dumps(extra, ensure_ascii=False)

        return payload

    def resolve_http_timeout(self, fallback_timeout=None):
        timeout_value = self.owner._resolve_timeout(fallback_timeout)
        if timeout_value is None:
            return None
        return max(float(timeout_value), 0.001)

    def parse_http_upload_response(self, response):
        try:
            payload = response.json()
        except Exception:
            payload = None
        return payload

    def build_http_upload_success_message(self, payload, file_path: str, fallback_message: str):
        if not isinstance(payload, dict):
            return fallback_message

        message = payload.get('message') or fallback_message
        data = payload.get('data') or {}

        original_name = data.get('original_name') or os.path.basename(file_path)
        stored_name = data.get('stored_name') or ''
        artifact_id = data.get('artifact_id') or ''
        download_url = data.get('download_url') or ''

        lines = [message, f'Original: {original_name}']
        if stored_name:
            lines.append(f'Stored: {stored_name}')
        if artifact_id:
            lines.append(f'Artifact ID: {artifact_id}')
        if download_url:
            lines.append(f'Download URL: {download_url}')

        return '\n'.join(lines)

    def upload_file_to_server_via_http(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        upload_url = UPLOAD_BASE_URL.rstrip('/') + '/api/files/upload'
        form_data = self.build_http_upload_form_data(
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
            extra=extra,
        )

        strategy = self.get_transfer_strategy()
        return strategy.upload_file(file_path, upload_url, form_data)

    def upload_single_file_to_server_result(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        file_size = os.path.getsize(file_path)

        self.owner._send_interim_result(1, f'Preparing HTTP upload: {file_path}', 0)
        self.owner._send_interim_result(1, f'File size: {file_size} bytes', 0)

        response = self.upload_file_to_server_via_http(
            file_path,
            artifact_type=artifact_type,
            category=category,
            # source_type=source_type,
            related_path=related_path,
            extra=extra,
        )
        response.raise_for_status()

        payload = self.parse_http_upload_response(response)
        message = self.build_http_upload_success_message(
            payload,
            file_path=file_path,
            fallback_message='HTTP upload completed'
        )
        return 1, message

    def upload_paths_as_zip_to_server_result(
        self,
        resolved_paths: list[str],
        *,
        archive_name: str = '',
        artifact_type: str = 'files',
        category: str = 'default',
        # source_type: str = 'client_upload',
        related_path: str = '',
        extra: dict | None = None,
    ):
        temp_archive_path = ''
        try:
            temp_archive_path = self.owner._create_zip_from_paths(
                resolved_paths,
                archive_name=archive_name
            )
            return self.upload_single_file_to_server_result(
                temp_archive_path,
                artifact_type=artifact_type,
                category=category,
                # source_type=source_type,
                related_path=related_path,
                extra=extra,
            )
        finally:
            if temp_archive_path and os.path.isfile(temp_archive_path):
                try:
                    os.remove(temp_archive_path)
                except Exception:
                    pass

    def download_file_from_http(self, url: str, target_path: str):
        strategy = self.get_transfer_strategy()
        return strategy.download_file(url, target_path)








