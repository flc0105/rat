class WebCommandExecutionApi:
    """
    Web 命令执行子外观。

    职责：
    - 提交 Web command
    - 提交 Web upload
    - 取消 Web task
    """

    def __init__(self, task_service):
        self.task_service = task_service

    def _normalize_client_id(self, client_id: str) -> str:
        value = (client_id or '').strip()
        if not value:
            raise ValueError('client_id is required')
        return value

    def _normalize_task_id(self, task_id: str) -> str:
        value = (task_id or '').strip()
        if not value:
            raise ValueError('task_id is required')
        return value

    def _normalize_command(self, command: str) -> str:
        value = (command or '').strip()
        if not value:
            raise ValueError('command is required')
        return value

    def _normalize_upload_payload(self, local_path: str, display_name: str, remote_path: str = '') -> dict:
        normalized_local_path = (local_path or '').strip()
        normalized_display_name = (display_name or '').strip()
        if not normalized_local_path:
            raise ValueError('local_path is required')
        if not normalized_display_name:
            raise ValueError('display_name is required')

        return {
            'local_path': normalized_local_path,
            'display_name': normalized_display_name,
            'remote_path': (remote_path or '').strip(),
        }

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.task_service.submit_web_command(
            self._normalize_client_id(client_id),
            self._normalize_command(command),
            tab_id=(tab_id or '').strip(),
        )

    def cancel_web_task(self, task_id: str):
        return self.task_service.cancel_web_task(self._normalize_task_id(task_id))

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        upload_payload = self._normalize_upload_payload(local_path, display_name, remote_path)
        return self.task_service.submit_web_upload(
            self._normalize_client_id(client_id),
            upload_payload['local_path'],
            upload_payload['display_name'],
            upload_payload['remote_path'],
            tab_id=(tab_id or '').strip(),
        )