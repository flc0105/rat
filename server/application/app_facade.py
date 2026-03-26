import os

from server.application.artifact.artifact_service import WebArtifactService
from server.application.artifact.remote_file_service import WebRemoteFileService
from server.application.command.executor import CommandExecutor
from server.application.connection.connection_service import WebConnectionService
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.application.jobs.background_job_service import BackgroundJobService
from server.application.jobs.background_job_store import BackgroundJobStore
from server.application.script.script_service import ScriptService
from server.application.tasks.task_runner import WebTaskRunner
from server.application.tasks.task_service import WebTaskService
from server.application.tasks.task_store import WebTaskStore
from server.web.event_bus import WebEventBus
from server.config.config import SCRIPT_JOBS_PATH  # 需要在 config 中添加



class ServerWebService:
    """
    Server 的 Web 门面服务。
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

        self.script_service = ScriptService(SCRIPT_JOBS_PATH)

    def _get_client_command_candidates(self, session):
        payload = session.info.get('command_manifest') or []
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

    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def create_web_connection(self, transport, addr, info: dict):
        return self.connection_service.create_web_connection(transport, addr, info)

    def handle_connection_registered(self, session):
        self.connection_service.handle_connection_registered(session)

    def handle_connection_closed(self, session):
        self.connection_service.handle_connection_closed(session)

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

    def publish_artifact_created(self, artifact_info: dict):
        if not isinstance(artifact_info, dict):
            return

        self.event_bus.publish('artifact_created', {
            'artifact_id': artifact_info.get('artifact_id', ''),
            'artifact_type': artifact_info.get('artifact_type', ''),
            'category': artifact_info.get('category', ''),
            'hostname': artifact_info.get('hostname', ''),
            'client_id': artifact_info.get('client_id', ''),
            'original_name': artifact_info.get('original_name', ''),
            'stored_name': artifact_info.get('stored_name', ''),
            'size': artifact_info.get('size', 0),
            'created_at': artifact_info.get('created_at', ''),
            'source_type': artifact_info.get('source_type', ''),
            'download_url': artifact_info.get('download_url', ''),
            'preview_url': artifact_info.get('preview_url', ''),
        })

    def get_command_candidates(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)

        client_candidates = self._get_client_command_candidates(session)
        server_candidates = CommandExecutor(session, self.server).get_command_candidates()

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
        session = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_history_for_connection(session)

    def get_command_execution_history(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_execution_history_for_connection(session)

    def clear_command_history(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        self.server.command_history.clear_history_for_connection(session)
        return None

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.task_service.submit_web_command(client_id, command, tab_id=tab_id)

    def cancel_web_task(self, task_id: str):
        return self.task_service.cancel_web_task(task_id)

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        return self.task_service.submit_web_upload(
            client_id,
            local_path,
            display_name,
            remote_path,
            tab_id=tab_id
        )

    def list_server_jobs(self) -> list[dict]:
        """列出所有可用的远程脚本"""
        return self.script_service.list_scripts()

    def get_server_job_content(self, script_name: str) -> str:
        """获取远程脚本内容"""
        return self.script_service.get_script_content(script_name)

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

    def delete_remote_paths(self, client_id: str, paths: list[str]):
        return self.remote_file_service.delete_paths(client_id, paths)

    def preview_remote_file(self, client_id: str, path: str):
        return self.remote_file_service.preview_file(client_id, path)

    def build_connection(self, transport, addr, info: dict):
        return self.create_web_connection(transport, addr, info)

    def on_connection_registered(self, session):
        self.handle_connection_registered(session)

    def on_connection_closed(self, session):
        self.handle_connection_closed(session)

    def submit_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.submit_web_command(client_id, command, tab_id=tab_id)

    def submit_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        return self.submit_web_upload(
            client_id,
            local_path,
            display_name,
            remote_path,
            tab_id=tab_id
        )

    #script



    # def save_remote_script(self, script_name: str, content: str) -> dict:
    #     """保存远程脚本"""
    #     return self.script_service.save_script(script_name, content)
    #
    # def delete_remote_script(self, script_name: str) -> dict:
    #     """删除远程脚本"""
    #     return self.script_service.delete_script(script_name)