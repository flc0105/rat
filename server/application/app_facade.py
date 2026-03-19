from server.application.artifact.artifact_service import WebArtifactService
from server.application.artifact.remote_file_service import WebRemoteFileService
from server.application.command.executor import CommandExecutor
from server.application.connection.connection_service import WebConnectionService
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.application.jobs.background_job_service import BackgroundJobService
from server.application.jobs.background_job_store import BackgroundJobStore
from server.application.tasks.task_runner import WebTaskRunner
from server.application.tasks.task_service import WebTaskService
from server.application.tasks.task_store import WebTaskStore
from server.web.event_bus import WebEventBus


class ServerWebService:
    """
    Server 的 Web 门面服务。

    职责：
    - 聚合应用侧各个子服务
    - 对外暴露稳定接口，避免 app.py / server.py 直接依赖过多内部实现
    """

    def __init__(self, server):
        self.server = server
        self.event_bus = WebEventBus()
        self.task_store = WebTaskStore()

        self.artifact_service = WebArtifactService()
        self.file_service = self.artifact_service
        self.remote_execution_service = RemoteExecutionService(self.server)

        self.remote_file_service = WebRemoteFileService(
            remote_execution_service=self.remote_execution_service,
            artifact_service=self.artifact_service,
        )

        self.connection_service = WebConnectionService(
            server=self.server,
            event_bus=self.event_bus,
            artifact_service=self.artifact_service,
        )

        self.task_runner = WebTaskRunner(
            server=self.server,
            event_bus=self.event_bus,
            task_store=self.task_store,
        )

        self.task_service = WebTaskService(
            server=self.server,
            task_store=self.task_store,
            file_service=self.file_service,
            task_runner=self.task_runner,
        )

        self.background_job_store = BackgroundJobStore()
        self.background_job_store.artifact_service = self.artifact_service
        self.server.command_history.artifact_service = self.artifact_service

        self.background_job_service = BackgroundJobService(
            event_bus=self.event_bus,
            job_store=self.background_job_store,
            remote_execution_service=self.remote_execution_service,
        )

    # ------------------ helpers ------------------ #
    def _collect_result(self, result_iter):
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    def _get_client_command_candidates(self, conn):
        payload = conn.info.get('command_manifest') or []
        if not isinstance(payload, list):
            return []

        result = []
        for item in payload:
            if not isinstance(item, dict):
                continue

            name = (item.get('name') or '').strip()
            template = (item.get('template') or name).strip()

            if not name or not template:
                continue

            result.append({
                'name': name,
                'template': template,
                'help': item.get('help', ''),
                'group': item.get('group', 'general'),
                'suggest': item.get('suggest', True),
                'source': item.get('source', 'client')
            })

        return result

    # ------------------ connection facade ------------------ #
    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def create_web_connection(self, conn, addr, info: dict):
        return self.connection_service.create_web_connection(conn, addr, info)

    def handle_connection_registered(self, connection):
        self.connection_service.handle_connection_registered(connection)

    def handle_connection_closed(self, conn):
        self.connection_service.handle_connection_closed(conn)

    # ------------------ artifact facade ------------------ #
    def list_artifacts(self, artifact_type: str = '', hostname: str = ''):
        return {
            'items': self.artifact_service.list_artifacts(artifact_type=artifact_type, hostname=hostname),
            'hostnames': self.artifact_service.list_artifact_hostnames(),
        }

    def delete_artifact(self, artifact_id: str):
        return self.artifact_service.delete_artifact(artifact_id)

    def clear_artifacts(self, artifact_type: str, hostname: str = ''):
        return self.artifact_service.clear_artifacts(artifact_type, hostname=hostname)

    def build_artifact_preview_payload(self, artifact_id: str):
        return self.artifact_service.build_preview_payload(artifact_id)

    def get_artifact_file_path(self, artifact_id: str):
        return self.artifact_service.get_artifact_file_path(artifact_id)

    def get_artifact_by_id(self, artifact_id: str):
        return self.artifact_service.get_artifact_by_id(artifact_id)

    # ------------------ command candidates facade ------------------ #
    def get_command_candidates(self, client_id: str):
        conn = self.server.get_target_connection_by_client_id(client_id)

        client_candidates = self._get_client_command_candidates(conn)
        server_candidates = CommandExecutor(conn, self.server).get_command_candidates()

        merged = []
        seen = set()

        for item in client_candidates + server_candidates:
            template = (item.get('template') or '').strip()
            if not template or template in seen:
                continue
            seen.add(template)
            merged.append(item)

        merged.sort(key=lambda item: (item.get('source', ''), item.get('template', '').lower()))
        return merged

    def get_command_history(self, client_id: str):
        conn = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_history_for_connection(conn)

    def get_command_execution_history(self, client_id: str):
        conn = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_execution_history_for_connection(conn)

    def clear_command_history(self, client_id: str):
        conn = self.server.get_target_connection_by_client_id(client_id)
        self.server.command_history.clear_history_for_connection(conn)
        return None

    # ------------------ task facade ------------------ #
    def submit_web_command(self, client_id: str, command: str):
        return self.task_service.submit_web_command(client_id, command)

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = ''):
        return self.task_service.submit_web_upload(client_id, local_path, display_name, remote_path)

    # ------------------ background job facade ------------------ #
    def list_background_jobs(self, client_id: str):
        return self.background_job_service.list_jobs(client_id)

    def list_available_background_jobs(self, client_id: str):
        return self.background_job_service.list_available_jobs(client_id)

    def start_background_job(self, client_id: str, job_name: str):
        return self.background_job_service.start_job(client_id, job_name)

    def stop_background_job(self, client_id: str, job_key: str):
        return self.background_job_service.stop_job(client_id, job_key)

    def ingest_background_job_report(self, payload: dict):
        return self.background_job_service.ingest_report(payload)

    # ------------------ remote file facade ------------------ #
    def browse_remote_directory(self, client_id: str, path: str = ''):
        return self.remote_file_service.browse_directory(client_id, path)

    def create_remote_directory(self, client_id: str, path: str):
        return self.remote_file_service.create_directory(client_id, path)

    def rename_remote_path(self, client_id: str, old_path: str, new_name: str):
        return self.remote_file_service.rename_path(client_id, old_path, new_name)

    def delete_remote_path(self, client_id: str, path: str):
        return self.remote_file_service.delete_path(client_id, path)

    def download_remote_file(self, client_id: str, path: str):
        return self.remote_file_service.download_file(client_id, path)

    def download_remote_paths_as_zip(self, client_id: str, paths: list[str], archive_name: str = ''):
        return self.remote_file_service.download_paths_as_zip(client_id, paths, archive_name)

    def preview_remote_file(self, client_id: str, path: str):
        return self.remote_file_service.preview_file(client_id, path)

    # ------------------ compatibility facade ------------------ #
    def build_connection(self, conn, addr, info: dict):
        return self.create_web_connection(conn, addr, info)

    def on_connection_registered(self, connection):
        self.handle_connection_registered(connection)

    def on_connection_closed(self, conn):
        self.handle_connection_closed(conn)

    def submit_command(self, client_id: str, command: str):
        return self.submit_web_command(client_id, command)

    def submit_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = ''):
        return self.submit_web_upload(client_id, local_path, display_name, remote_path)