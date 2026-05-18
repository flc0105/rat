import json
import os

from client.commands.strategies.http_transfer.factory import build_http_transfer_strategy
from client.http.client_api import ClientApiClient
from core.utils.output_marker import info, success


class CommandHttpFileTransferService:
    """
    HTTP 文件传输服务。

    职责：
    - 从 CommandFileWebMixin 中抽离 HTTP 上传/下载基础设施
    - 显式承接 HTTP 传输策略、表单构造、响应解析等逻辑
    - 让命令 mixin 只保留“命令入口 + 参数组织”，减少横向隐式耦合
    """

    def __init__(self, owner, archive_service=None, client_api=None):
        self.owner = owner
        self.archive_service = archive_service
        self.client_api = client_api or getattr(owner, 'client_api', None) or ClientApiClient()

    def get_transfer_strategy(self):
        transfer_mode = getattr(self.owner, 'HTTP_TRANSFER_MODE', '')
        return build_http_transfer_strategy(self.owner, transfer_mode)

    def build_http_upload_form_data(
        self,
        *,
        artifact_type: str,
        category: str,
        extra: dict | None = None,
    ) -> dict:
        client_id = getattr(self.owner.socket, 'client_id', '') or ''

        payload = {
            'artifact_type': (artifact_type or 'files').strip() or 'files',
            'category': (category or '').strip() or 'default',
            'client_id': client_id,
            'source_command_id': self.owner.command_id if self.owner.command_id is not None else '',
        }

        if isinstance(extra, dict) and extra:
            payload['extra'] = json.dumps(extra, ensure_ascii=False)

        return payload

    def parse_http_upload_response(self, response):
        return self.client_api.try_parse_json(response)

    def build_http_upload_success_message(self, payload, file_path: str, fallback_message: str):
        if not isinstance(payload, dict):
            return fallback_message

        message = payload.get('message') or fallback_message
        data = payload.get('data') or {}

        original_name = data.get('original_name') or os.path.basename(file_path)
        stored_name = data.get('stored_name') or ''
        artifact_id = data.get('artifact_id') or ''
        download_url = data.get('download_url') or ''

        # lines = [message, f'Original: {original_name}']
        # if stored_name:
        #     lines.append(f'Stored: {stored_name}')
        # if artifact_id:
        #     lines.append(f'Artifact ID: {artifact_id}')
        # if download_url:
        #     lines.append(f'Download URL: {download_url}')

        lines = [success(message), info(f'Original: {original_name}')]
        if stored_name:
            lines.append(info(f'Stored: {stored_name}'))
        if artifact_id:
            lines.append(info(f'Artifact ID: {artifact_id}'))
        if download_url:
            lines.append(info(f'Download URL: {download_url}'))

        return '\n'.join(lines)

    def upload_file_to_server_via_http(
        self,
        file_path: str,
        *,
        artifact_type: str = 'files',
        category: str = 'default',
        extra: dict | None = None,
    ):
        upload_url = self.client_api.build_file_upload_url()
        form_data = self.build_http_upload_form_data(
            artifact_type=artifact_type,
            category=category,
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
        extra: dict | None = None,
    ):
        file_size = os.path.getsize(file_path)


        self.owner._send_info(f'Preparing HTTP upload: {file_path}', 0)
        self.owner._send_info(f'File size: {file_size} bytes', 0)

        response = self.upload_file_to_server_via_http(
            file_path,
            artifact_type=artifact_type,
            category=category,
            extra=extra,
        )
        response.raise_for_status()

        payload = self.parse_http_upload_response(response)
        message = self.build_http_upload_success_message(
            payload,
            file_path=file_path,
            fallback_message='HTTP upload completed',
        )
        return 1, message

    def upload_paths_as_zip_to_server_result(
        self,
        resolved_paths: list[str],
        *,
        archive_name: str = '',
        artifact_type: str = 'files',
        category: str = 'default',
        extra: dict | None = None,
    ):
        if self.archive_service is None:
            raise RuntimeError('archive_service is required')

        temp_archive_path = ''
        try:
            temp_archive_path = self.archive_service.create_zip_from_paths(
                resolved_paths,
                archive_name=archive_name,
            )
            return self.upload_single_file_to_server_result(
                temp_archive_path,
                artifact_type=artifact_type,
                category=category,
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
        return strategy.download_file(
            self.client_api.normalize_server_url(url),
            target_path,
        )