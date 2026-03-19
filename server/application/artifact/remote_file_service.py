import base64
import json


class WebRemoteFileService:
    """
    远程文件应用服务。

    职责：
    - 调用客户端目录浏览命令
    - 调用客户端删除命令
    - 调用客户端下载命令
    - 将客户端返回结果转换成上层可直接消费的数据
    """

    def __init__(self, remote_execution_service, artifact_service):
        self.remote_execution_service = remote_execution_service
        self.artifact_service = artifact_service

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _build_command(self, name: str, payload: dict | None = None) -> str:
        if not payload:
            return name
        return f'{name} {self._encode_payload_arg(payload)}'

    def browse_directory(self, client_id: str, path: str = '') -> dict:
        """
        浏览远程目录
        """
        command = self._build_command('browse_dir', {'path': path})
        payload = self.remote_execution_service.run_json_command(client_id, command)

        return {
            'current_path': payload.get('current_path', ''),
            'parent_path': payload.get('parent_path'),
            'entries': payload.get('entries', [])
        }

    def delete_path(self, client_id: str, path: str) -> dict:
        """
        删除远程路径
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        command = self._build_command('delete_path', {'path': path})
        result_text = self.remote_execution_service.run_text_command(client_id, command)

        return {
            'path': path,
            'message': result_text
        }

    def create_directory(self, client_id: str, path: str) -> dict:
        """
        创建远程目录
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        command = self._build_command('mkdir_path', {'path': path})
        result_text = self.remote_execution_service.run_text_command(client_id, command)

        return {
            'path': path,
            'message': result_text
        }

    def rename_path(self, client_id: str, old_path: str, new_name: str) -> dict:
        """
        重命名远程文件或目录
        """
        if not (old_path or '').strip():
            raise ValueError('old_path is required')
        if not (new_name or '').strip():
            raise ValueError('new_name is required')

        command = self._build_command('rename_path', {
            'old_path': old_path,
            'new_name': new_name
        })
        result_text = self.remote_execution_service.run_text_command(client_id, command)

        return {
            'old_path': old_path,
            'new_name': new_name,
            'message': result_text
        }

    def download_file(self, client_id: str, path: str, history_entry_id: str = '') -> dict:
        """
        下载远程文件到服务端 artifact downloads 区，并返回下载信息
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        result = self.remote_execution_service.fetch_artifact(
            client_id,
            command,
            artifact_type='downloads',
            source_type='remote_download',
            related_path=normalized_path,
            history_entry_id=history_entry_id,
        )

        return {
            'path': normalized_path,
            'message': result['message'],
            'artifact': result['artifact'],
        }

    def download_paths_as_zip(
        self,
        client_id: str,
        paths: list[str],
        archive_name: str = '',
        history_entry_id: str = '',
    ) -> dict:
        """
        将多个远程路径打包为 zip 下载到服务端 artifact downloads 区
        """
        if not isinstance(paths, list) or not paths:
            raise ValueError('paths is required')

        normalized_paths = [
            str(item or '').strip()
            for item in paths
            if str(item or '').strip()
        ]
        if not normalized_paths:
            raise ValueError('paths is required')

        command = self._build_command('download_paths', {
            'paths': normalized_paths,
            'archive_name': archive_name,
        })

        result = self.remote_execution_service.fetch_artifact(
            client_id,
            command,
            artifact_type='downloads',
            source_type='remote_download_bundle',
            related_path='\n'.join(normalized_paths),
            history_entry_id=history_entry_id,
        )

        return {
            'paths': normalized_paths,
            'message': result['message'],
            'artifact': result['artifact'],
        }

    def preview_file(self, client_id: str, path: str, history_entry_id: str = '') -> dict:
        """
        预览远程文件：
        - 拉取到 previews 目录
        - 复用统一 artifact 预览逻辑
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        result = self.remote_execution_service.fetch_artifact(
            client_id,
            command,
            artifact_type='previews',
            source_type='remote_preview',
            related_path=normalized_path,
            history_entry_id=history_entry_id,
        )
        artifact = result['artifact']

        return self.artifact_service.build_preview_payload(artifact.get('artifact_id', ''))