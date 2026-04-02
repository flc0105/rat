import os

from server.application.assembly import ServerApplicationAssembly


class ServerWebService:
    """
    Server 的 Web 门面服务。

    约束：
    - 这里只保留正式接口名
    - 不再保留内部兼容别名
    - 调用方必须显式迁移到正式方法
    """

    def __init__(self, server, assembly=None):
        self.server = server
        self.assembly = assembly or ServerApplicationAssembly(server)

        # ------------------ 装配后的依赖引用 ------------------ #
        self.event_bus = self.assembly.event_bus
        self.task_store = self.assembly.task_store

        self.artifact_service = self.assembly.artifact_service
        self.file_service = self.assembly.file_service
        self.remote_execution_service = self.assembly.remote_execution_service
        self.remote_file_service = self.assembly.remote_file_service
        self.connection_service = self.assembly.connection_service
        self.command_executor_factory = self.assembly.command_executor_factory
        self.task_runner = self.assembly.task_runner
        self.task_service = self.assembly.task_service
        self.background_job_store = self.assembly.background_job_store
        self.background_job_service = self.assembly.background_job_service
        self.script_service = self.assembly.script_service
        self.agent_builder = self.assembly.agent_builder

    @classmethod
    def from_server(cls, server):
        """
        默认构建入口：
        - 先完成 application assembly
        - 再创建 facade
        """
        assembly = ServerApplicationAssembly(server)
        return cls(server, assembly=assembly)

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

    # ------------------ connection api ------------------ #
    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def create_web_connection(self, transport, addr, info: dict):
        return self.connection_service.create_web_connection(transport, addr, info)

    def handle_connection_registered(self, session):
        self.connection_service.handle_connection_registered(session)

    def handle_connection_closed(self, session):
        self.connection_service.handle_connection_closed(session)

    # ------------------ artifact api ------------------ #
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

    def bind_uploaded_artifact_to_history(self, client_id: str, source_command_id, artifact: dict) -> bool:
        """
        将上传完成的 artifact 挂回到对应 history entry。
        """
        if not client_id or source_command_id is None:
            return False

        if not isinstance(artifact, dict) or not artifact:
            return False

        try:
            session = self.server.get_target_connection_by_client_id(client_id)
        except Exception:
            return False

        return bool(
            self.server.command_history_orchestrator.bind_uploaded_artifact(
                session,
                source_command_id,
                artifact
            )
        )

    # ------------------ command/history api ------------------ #
    def get_command_candidates(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)

        client_candidates = self._get_client_command_candidates(session)
        server_candidates = self.command_executor_factory.create(session).get_command_candidates()

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

    def set_command_history_pinned(self, client_id: str, command: str, is_pinned: bool):
        session = self.server.get_target_connection_by_client_id(client_id)
        changed = self.server.command_history.set_command_pinned_for_connection(
            session,
            command,
            is_pinned,
        )
        return {
            'command': (command or '').strip(),
            'is_pinned': bool(is_pinned),
            'changed': bool(changed),
        }

    def delete_command_execution_history_entry(self, client_id: str, entry_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        deleted = self.server.command_history.delete_execution_entry_for_connection(session, entry_id)
        return {
            'entry_id': (entry_id or '').strip(),
            'deleted': bool(deleted),
        }

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.task_service.submit_web_command(client_id, command, tab_id=tab_id)

    def cancel_web_task(self, task_id: str):
        return self.task_service.cancel_web_task(task_id)

    def submit_web_upload(
        self,
        client_id: str,
        local_path: str,
        display_name: str,
        remote_path: str = '',
        tab_id: str = '',
    ):
        return self.task_service.submit_web_upload(
            client_id,
            local_path,
            display_name,
            remote_path,
            tab_id=tab_id
        )

    # ------------------ server job api ------------------ #
    def list_server_jobs(self) -> list[dict]:
        return self.script_service.list_scripts()

    def get_server_job_content(self, script_name: str) -> str:
        return self.script_service.get_script_content(script_name)

    def save_server_job_content(self, script_name, content):
        return self.script_service.save_script(script_name, content)

    def upload_server_job(self, file_storage):
        return self.script_service.upload_script(file_storage)

    def delete_server_job(self, script_name: str):
        return self.script_service.delete_script(script_name)

    # ------------------ background job api ------------------ #
    def list_background_jobs(self, client_id: str):
        return self.background_job_service.list_jobs(client_id)

    def list_available_background_jobs(self, client_id: str):
        return self.background_job_service.list_available_jobs(client_id)

    def start_background_job(self, client_id: str, job_name: str, source: str = 'auto'):
        return self.background_job_service.start_job(client_id, job_name)

    def stop_background_job(self, client_id: str, job_key: str):
        return self.background_job_service.stop_job(client_id, job_key)

    def ingest_background_job_report(self, payload: dict):
        return self.background_job_service.ingest_report(payload)

    # ------------------ remote file api ------------------ #
    def browse_remote_directory(
        self,
        client_id: str,
        path: str = '',
        page: int = 1,
        page_size: int = 100,
        show_hidden: bool = False,
    ):
        return self.remote_file_service.browse_directory(
            client_id,
            path,
            page=page,
            page_size=page_size,
            show_hidden=show_hidden,
        )

    def create_remote_directory(self, client_id: str, path: str):
        return self.remote_file_service.create_directory(client_id, path)

    def rename_remote_path(self, client_id: str, old_path: str, new_name: str):
        return self.remote_file_service.rename_path(client_id, old_path, new_name)

    def delete_remote_path(self, client_id: str, path: str):
        return self.remote_file_service.delete_path(client_id, path)

    def delete_remote_paths(self, client_id: str, paths: list[str]):
        return self.remote_file_service.delete_paths(client_id, paths)

    def preview_remote_file(
        self,
        client_id: str,
        path: str,
        history_entry_id: str = '',
    ):
        return self.remote_file_service.preview_file(
            client_id,
            path,
            history_entry_id=history_entry_id,
        )

    def download_remote_file(
        self,
        client_id: str,
        path: str,
        history_entry_id: str = '',
    ):
        return self.remote_file_service.download_file(
            client_id,
            path,
            history_entry_id=history_entry_id,
        )

    def download_remote_paths_as_zip(
        self,
        client_id: str,
        paths: list[str],
        archive_name: str = '',
        history_entry_id: str = '',
    ):
        return self.remote_file_service.download_paths_as_zip(
            client_id,
            paths,
            archive_name=archive_name,
            history_entry_id=history_entry_id,
        )

    def read_remote_file(
        self,
        client_id: str,
        path: str,
        encoding: str = 'utf-8',
        max_bytes: int = 200000,
    ):
        return self.remote_file_service.get_file_content(client_id, path)

    def save_remote_file(
        self,
        client_id: str,
        path: str,
        content: str,
        encoding: str = 'utf-8',
    ):
        return self.remote_file_service.save_file_content(
            client_id,
            path,
            content,
            encoding=encoding,
        )

    # ------------------ agent api ------------------ #
    def build_agent(
        self,
        server_host: str,
        server_port: int,
        web_port: int = None,
        target_os: str = 'mac',
        builder: str = 'pyinstaller',
        target_arch: str = 'auto',
    ):
        return self.agent_builder.build_agent(
            server_host=server_host,
            server_port=server_port,
            web_port=web_port,
            target_os=target_os,
            builder=builder,
            target_arch=target_arch,
        )

    def cleanup_agent_build(self, work_dir: str):
        if not work_dir:
            return
        self.agent_builder.cleanup_build_dir(work_dir)