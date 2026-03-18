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

    def __init__(self, server):
        self.server = server

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

    def _fetch_file_to_custom_dir(self, client_id: str, path: str, target_dir: str, write_meta: bool = False):
        """
        将远程文件拉取到指定服务端目录，不进入 recent downloads
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        conn = self.server.get_target_connection_by_client_id(client_id)
        command_id = conn._generate_message_id()
        conn.set_file_receive_context(
            command_id,
            target_dir=target_dir,
            write_meta=write_meta,
            on_file_saved=None,
        )

        data = {
            'type': 'command',
            'id': command_id,
            'text': command,
        }
        conn.send(data)

        status, text = self._collect_result(conn.wait_for_result(command_id, command))
        if status != 1:
            raise RuntimeError(text or 'Remote file fetch failed')

        return text

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
        下载远程文件到服务端接收区，并返回下载信息
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', {'path': normalized_path})

        conn = self.server.get_target_connection_by_client_id(client_id)
        before_files = {item['saved_name'] for item in self.server.web_service.file_service.list_received_files()}

        status, text = self._collect_result(conn.send_command(command))
        if status != 1:
            raise RuntimeError(text or 'Remote download failed')

        after_items = self.server.web_service.file_service.list_received_files()
        target_item = None

        for item in after_items:
            if item['saved_name'] not in before_files and item.get('client_id') == client_id:
                target_item = item
                break

        if not target_item:
            base_name = os.path.basename(normalized_path)
            for item in after_items:
                if item.get('client_id') == client_id and (
                    item.get('original_name') == base_name or item.get('saved_name') == base_name
                ):
                    target_item = item
                    break

        if not target_item:
            raise RuntimeError('Remote file download completed, but saved file was not found')

        return {
            'path': normalized_path,
            'message': text,
            'file': target_item
        }

    def preview_file(self, client_id: str, path: str) -> dict:
        """
        预览远程文件：
        - 拉取到 preview 目录
        - 不进入 recent downloads
        - 复用现有图片/文本预览逻辑
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        conn = self.server.get_target_connection_by_client_id(client_id)
        hostname = conn.info.get('hostname') or 'unknown_host'
        target_dir = self.server.web_service.file_service.get_preview_dir_for_hostname(hostname)

        normalized_path = path.strip()
        base_name = os.path.basename(normalized_path)

        before_names = set(os.listdir(target_dir)) if os.path.isdir(target_dir) else set()

        self._fetch_file_to_custom_dir(
            client_id=client_id,
            path=normalized_path,
            target_dir=target_dir,
            write_meta=False,
        )

        after_names = set(os.listdir(target_dir)) if os.path.isdir(target_dir) else set()
        new_names = [name for name in (after_names - before_names) if os.path.isfile(os.path.join(target_dir, name))]

        saved_name = None
        if new_names:
            new_names.sort()
            saved_name = new_names[0]
        else:
            candidate = os.path.join(target_dir, base_name)
            if os.path.isfile(candidate):
                saved_name = base_name
            else:
                prefix, ext = os.path.splitext(base_name)
                matches = [
                    name for name in after_names
                    if name == base_name or (name.startswith(prefix + '_') and name.endswith(ext))
                ]
                matches.sort()
                if matches:
                    saved_name = matches[-1]

        if not saved_name:
            raise RuntimeError('Preview file was received, but saved file was not found')

        relative_path = self.server.web_service.file_service.build_preview_relative_path(hostname, saved_name)
        return self.server.web_service.file_service.build_preview_file_payload(relative_path)