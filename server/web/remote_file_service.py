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

    def _build_command(self, name: str, arg: str = '') -> str:
        value = (arg or '').strip()
        if not value:
            return name
        return f'{name} {value}'

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

    def browse_directory(self, client_id: str, path: str = '') -> dict:
        """
        浏览远程目录
        """
        command = self._build_command('browse_dir', path)
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

        command = self._build_command('delete_path', path)
        result_text = self._run_text_command(client_id, command)

        return {
            'path': path,
            'message': result_text
        }

    def download_file(self, client_id: str, path: str) -> dict:
        """
        下载远程文件到服务端接收区，并返回下载信息
        """
        if not (path or '').strip():
            raise ValueError('path is required')

        normalized_path = path.strip()
        command = self._build_command('download_path', normalized_path)

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