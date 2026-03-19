import base64
import json
import os


class WebRemoteFileService:
    """
    Web 远程文件服务。

    职责：
    - 调用客户端目录浏览命令
    - 调用客户端删除命令
    - 调用客户端下载命令
    - 将客户端返回结果转换成 Web 端可直接消费的数据
    """

    def __init__(self, server, artifact_service):
        self.server = server
        self.artifact_service = artifact_service

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _build_command(self, name: str, payload: dict | None = None) -> str:
        if not payload:
            return name
        return f'{name} {self._encode_payload_arg(payload)}'

    def _collect_result(self, result_iter):
        """
        收集命令执行结果
        """
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    def _run_text_command(self, client_id: str, command: str) -> str:
        conn = self.server.get_target_connection_by_client_id(client_id)
        status, text = self._collect_result(conn.send_command(command))

        if status != 1:
            raise RuntimeError(text or 'Remote command failed')

        return text

    def _run_json_command(self, client_id: str, command: str) -> dict:
        text = self._run_text_command(client_id, command)

        try:
            return json.loads(text or '{}')
        except Exception as e:
            raise RuntimeError(f'Invalid remote JSON payload: {e}')

    def _fetch_artifact(self, client_id: str, command: str, *, artifact_type: str, source_type: str, related_path: str = '') -> dict:
        conn = self.server.get_target_connection_by_client_id(client_id)
        command_id = conn._generate_message_id()
        capture_result = {}

        conn.set_file_receive_context(
            command_id,
            artifact_type=artifact_type,
            source_type=source_type,
            related_path=related_path,
            source_command_id=command_id,
            capture_result=capture_result,
        )

        conn.send({
            'type': 'command',
            'id': command_id,
            'text': command,
        })

        status, text = self._collect_result(conn.wait_for_result(command_id, command))
        if status != 1:
            raise RuntimeError(text or 'Remote file fetch failed')

        artifact = capture_result.get('artifact') or {}
        if not isinstance(artifact, dict) or not artifact.get('artifact_id'):
            raise RuntimeError('Remote file download completed, but artifact was not found')

        return {
            'message': text,
            'artifact': artifact,
        }

    def browse_directory(self, client_id: str, path: str = '') -> dict:
        """
        浏览远程目录
        """
        command = self._build_command('browse_dir', {'path': path})
        payload = self._run_json_command(client_id, command)

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
        result_text = self._run_text_command(client_id, command)

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
        result_text = self._run_text_command(client_id, command)

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
        result_text = self._run_text_command(client_id, command)

        return {
            'old_path': old_path,
            'new_name': new_name,
            'message': result_text
        }

    def download_file(self, client_id: str, path: str) -> dict:
        """
        下载远程文件到服务端 artifact downloads 区，并返回下载信息
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        result = self._fetch_artifact(
            client_id=client_id,
            command=command,
            artifact_type='downloads',
            source_type='remote_download',
            related_path=normalized_path,
        )

        return {
            'path': normalized_path,
            'message': result['message'],
            'artifact': result['artifact']
        }

    def download_paths_as_zip(self, client_id: str, paths: list[str], archive_name: str = '') -> dict:
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

        result = self._fetch_artifact(
            client_id=client_id,
            command=command,
            artifact_type='downloads',
            source_type='remote_download_bundle',
            related_path='\n'.join(normalized_paths),
        )

        return {
            'paths': normalized_paths,
            'message': result['message'],
            'artifact': result['artifact']
        }

    def preview_file(self, client_id: str, path: str) -> dict:
        """
        预览远程文件：
        - 拉取到 previews 目录
        - 复用统一 artifact 预览逻辑
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        result = self._fetch_artifact(
            client_id=client_id,
            command=command,
            artifact_type='previews',
            source_type='remote_preview',
            related_path=normalized_path,
        )
        artifact = result['artifact']

        return self.artifact_service.build_preview_payload(artifact.get('artifact_id', ''))
