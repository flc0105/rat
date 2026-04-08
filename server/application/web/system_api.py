import json


class WebSystemInspectionApi:
    """
    Web 系统检查子外观。

    职责：
    - 提供 system paths 查询
    - 提供 process/app 列表查询
    - 提供 process detail 查询
    - 提供 process/app kill 能力

    说明：
    - 不负责 HTTP 参数解析
    - 不负责响应封装
    - 统一承载 system inspection 相关 Web 应用动作
    """

    def __init__(self, server, remote_execution_service):
        self.server = server
        self.remote_execution_service = remote_execution_service

    def _get_session(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    def _run_process_command(self, client_id: str, command: str):
        return self.remote_execution_service.run_foreground_text_command(
            client_id,
            command,
            task_type='process',
            source='web_process',
        )

    def _load_json_or_default(self, text: str, default):
        try:
            return json.loads(text)
        except Exception:
            return default

    def get_system_paths(self, client_id: str):
        session = self._get_session(client_id)
        return session.info.get('system_paths', {})

    def list_processes(self, client_id: str):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, 'list_processes')
        return self._load_json_or_default(result_text, [])

    def get_process_detail(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'get_process_detail {pid}')
        return self._load_json_or_default(result_text, {})

    def kill_process(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'kill_process {pid}')
        return {'message': result_text}

    def list_apps(self, client_id: str):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, 'list_apps')
        return self._load_json_or_default(result_text, [])

    def kill_app(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'kill_process {pid}')
        return {'message': result_text}