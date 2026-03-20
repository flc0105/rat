import base64
import json


class WebRemoteFileService:
    """
    远程文件应用服务。

    当前文件链路：
    - 普通下载：进入 artifact files 区
    - 预览下载：进入 artifact previews 区
    - client 在命令结果文本中返回 Artifact ID
    - server 再根据 Artifact ID 查询 artifact
    """

    RESULT_ARTIFACT_ID_PREFIX = 'Artifact ID:'

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

    def _extract_artifact_id_from_result_text(self, text: str) -> str:
        lines = [str(line).strip() for line in str(text or '').splitlines()]
        for line in lines:
            if line.startswith(self.RESULT_ARTIFACT_ID_PREFIX):
                return line[len(self.RESULT_ARTIFACT_ID_PREFIX):].strip()
        return ''

    def _resolve_artifact_from_result_text(self, result_text: str) -> dict:
        artifact_id = self._extract_artifact_id_from_result_text(result_text)
        if not artifact_id:
            raise RuntimeError(
                'Remote file command completed, but Artifact ID was not found in result text'
            )

        artifact = self.artifact_service.get_artifact_by_id(artifact_id)
        if not isinstance(artifact, dict) or not artifact.get('artifact_id'):
            raise RuntimeError('Artifact was not found after HTTP upload completed')

        return artifact

    def browse_directory(self, client_id: str, path: str = '') -> dict:
        command = self._build_command('browse_dir', {'path': path})
        payload = self.remote_execution_service.run_json_command(client_id, command)

        return {
            'current_path': payload.get('current_path', ''),
            'parent_path': payload.get('parent_path'),
            'entries': payload.get('entries', [])
        }

    def delete_path(self, client_id: str, path: str) -> dict:
        if not (path or '').strip():
            raise ValueError('path is required')

        command = self._build_command('delete_path', {'path': path})
        result_text = self.remote_execution_service.run_text_command(client_id, command)

        return {
            'path': path,
            'message': result_text
        }

    def create_directory(self, client_id: str, path: str) -> dict:
        if not (path or '').strip():
            raise ValueError('path is required')

        command = self._build_command('mkdir_path', {'path': path})
        result_text = self.remote_execution_service.run_text_command(client_id, command)

        return {
            'path': path,
            'message': result_text
        }

    def rename_path(self, client_id: str, old_path: str, new_name: str) -> dict:
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
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        result_text = self.remote_execution_service.run_text_command(
            client_id,
            command,
            history_entry_id=history_entry_id,
        )
        artifact = self._resolve_artifact_from_result_text(result_text)

        return {
            'path': normalized_path,
            'message': result_text,
            'artifact': artifact,
        }

    def download_paths_as_zip(
        self,
        client_id: str,
        paths: list[str],
        archive_name: str = '',
        history_entry_id: str = '',
    ) -> dict:
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

        result_text = self.remote_execution_service.run_text_command(
            client_id,
            command,
            history_entry_id=history_entry_id,
        )
        artifact = self._resolve_artifact_from_result_text(result_text)

        return {
            'paths': normalized_paths,
            'message': result_text,
            'artifact': artifact,
        }

    def preview_file(self, client_id: str, path: str, history_entry_id: str = '') -> dict:
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('preview_path', {'path': normalized_path})

        result_text = self.remote_execution_service.run_text_command(
            client_id,
            command,
            history_entry_id=history_entry_id,
        )
        artifact = self._resolve_artifact_from_result_text(result_text)

        return self.artifact_service.build_preview_payload(artifact.get('artifact_id', ''))