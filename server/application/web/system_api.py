import json
import threading

from server.application.web.process_snapshot_cache import ProcessSnapshotCache


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

    PROCESS_SNAPSHOT_TYPE = 'processes'
    APP_SNAPSHOT_TYPE = 'apps'

    def __init__(self, server, remote_execution_service, process_snapshot_cache=None):
        self.server = server
        self.remote_execution_service = remote_execution_service
        self.process_snapshot_cache = process_snapshot_cache or ProcessSnapshotCache()

    def _get_session(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    def _build_snapshot_target_key(self, session, client_id: str) -> str:
        hostname = str(getattr(session.session_info, 'hostname', '') or '').strip()
        if hostname:
            return f'host::{hostname}'
        return f'client::{client_id}'

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

    def _get_snapshot_command(self, snapshot_type: str) -> str:
        if snapshot_type == self.APP_SNAPSHOT_TYPE:
            return 'list_apps'
        return 'list_processes'

    def _get_snapshot_default(self, snapshot_type: str):
        return []

    def _refresh_snapshot_sync(self, client_id: str, snapshot_type: str, *, session=None):
        session = session or self._get_session(client_id)
        target_key = self._build_snapshot_target_key(session, client_id)
        command = self._get_snapshot_command(snapshot_type)
        default_value = self._get_snapshot_default(snapshot_type)

        result_text = self._run_process_command(client_id, command)
        data = self._load_json_or_default(result_text, default_value)
        self.process_snapshot_cache.store_snapshot(target_key, snapshot_type, data)
        return data

    def _refresh_snapshot_in_background(self, client_id: str, snapshot_type: str, target_key: str):
        try:
            self._refresh_snapshot_sync(client_id, snapshot_type)
        except Exception:
            # 后台刷新失败时保留旧缓存，避免影响前台操作体验。
            pass
        finally:
            self.process_snapshot_cache.end_refresh(target_key, snapshot_type)

    def _schedule_snapshot_refresh(self, client_id: str, snapshot_type: str, *, target_key: str):
        if not self.process_snapshot_cache.begin_refresh(target_key, snapshot_type):
            return

        threading.Thread(
            target=self._refresh_snapshot_in_background,
            args=(client_id, snapshot_type, target_key),
            daemon=True,
        ).start()

    def _get_snapshot_list(self, client_id: str, snapshot_type: str):
        session = self._get_session(client_id)
        target_key = self._build_snapshot_target_key(session, client_id)
        snapshot = self.process_snapshot_cache.get_snapshot(target_key, snapshot_type)

        if snapshot.get('has_data') and not snapshot.get('is_stale'):
            return snapshot.get('data') or []

        if snapshot.get('has_data'):
            self._schedule_snapshot_refresh(
                client_id,
                snapshot_type,
                target_key=target_key,
            )
            return snapshot.get('data') or []

        return self._refresh_snapshot_sync(
            client_id,
            snapshot_type,
            session=session,
        )

    def _invalidate_process_snapshots(self, client_id: str):
        session = self._get_session(client_id)
        target_key = self._build_snapshot_target_key(session, client_id)
        self.process_snapshot_cache.invalidate(target_key)

    def get_system_paths(self, client_id: str):
        session = self._get_session(client_id)
        return session.session_info.system_paths

    def list_processes(self, client_id: str):
        return self._get_snapshot_list(client_id, self.PROCESS_SNAPSHOT_TYPE)

    def get_process_detail(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'get_process_detail {pid}')
        return self._load_json_or_default(result_text, {})

    def kill_process(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'kill_process {pid}')
        self._invalidate_process_snapshots(client_id)
        return {'message': result_text}

    def list_apps(self, client_id: str):
        return self._get_snapshot_list(client_id, self.APP_SNAPSHOT_TYPE)

    def kill_app(self, client_id: str, pid: int):
        self._get_session(client_id)
        result_text = self._run_process_command(client_id, f'kill_process {pid}')
        self._invalidate_process_snapshots(client_id)
        return {'message': result_text}
