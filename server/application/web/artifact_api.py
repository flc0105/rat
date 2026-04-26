import json
import os
from datetime import datetime


class WebArtifactApi:
    def __init__(self, server, event_bus, artifact_service):
        self.server = server
        self.event_bus = event_bus
        self.artifact_service = artifact_service

    def list_artifacts(self, artifact_type: str = '', machine_id: str = ''):
        return {
            'items': self.artifact_service.list_artifacts(artifact_type=artifact_type, machine_id=machine_id),
            'machines': self.artifact_service.list_artifact_machines(),
        }

    def delete_artifact(self, artifact_id: str):
        return self.artifact_service.delete_artifact(artifact_id)

    def clear_artifacts(self, artifact_type: str, machine_id: str = ''):
        return self.artifact_service.clear_artifacts(artifact_type, machine_id=machine_id)

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
            'machine_id': artifact_info.get('machine_id', ''),
            'client_id': artifact_info.get('client_id', ''),
            'original_name': artifact_info.get('original_name', ''),
            'stored_name': artifact_info.get('stored_name', ''),
            'size': artifact_info.get('size', 0),
            'created_at': artifact_info.get('created_at', ''),
            # 'source_type': artifact_info.get('source_type', ''),
            'download_url': artifact_info.get('download_url', ''),
            'preview_url': artifact_info.get('preview_url', ''),
        })

    def bind_uploaded_artifact_to_history(self, client_id: str, source_command_id, artifact: dict) -> bool:
        if not client_id or source_command_id is None:
            return False
        if not isinstance(artifact, dict) or not artifact:
            return False
        try:
            session = self.server.get_target_connection_by_client_id(client_id)
        except Exception:
            return False
        return bool(self.server.command_history_orchestrator.bind_uploaded_artifact(session, source_command_id, artifact))

    def resolve_client_context(self, client_id: str) -> tuple[str, str, str]:
        hostname = ''
        machine_id = ''
        addr = ''
        if not client_id:
            return hostname, machine_id, addr
        try:
            conn = self.server.get_target_connection_by_client_id(client_id)
            conn_info = getattr(conn, 'session_info', None)
            hostname = getattr(conn_info, 'hostname', '') or ''
            machine_id = getattr(conn_info, 'machine_id', '') or ''
            addr = getattr(conn_info, 'addr', '') or ''
        except Exception:
            pass
        return hostname, machine_id, addr

    def create_upload_temp_file(self, upload):
        return self.artifact_service.create_upload_temp_file(upload)

    def get_upload_temp_file_path(self, temp_id: str, filename: str):
        return self.artifact_service.get_upload_temp_file_path(temp_id, filename)

    def save_http_uploaded_file(self, upload, artifact_type: str = 'files', category: str = '', client_id: str = '',
                                hostname: str = '', machine_id: str = '', job_id: str = '', job_name: str = '',
                                job_key: str = '',
                                # source_type: str = 'client_upload',
                                related_path: str = '',
                                source_command_id=None, extra=None):
        resolved_hostname, resolved_machine_id, addr = self.resolve_client_context(client_id)
        hostname = hostname or resolved_hostname
        machine_id = machine_id or resolved_machine_id
        artifact = self.artifact_service.save_http_uploaded_file(
            upload,
            artifact_type=artifact_type,
            category=category,
            client_id=client_id,
            hostname=hostname,
            machine_id=machine_id,
            job_id=job_id,
            job_name=job_name,
            job_key=job_key,
            # source_type=source_type,
            source_command_id=source_command_id,
            addr=addr,
            related_path=related_path,
            extra=extra,
        )
        try:
            self.bind_uploaded_artifact_to_history(client_id, source_command_id, artifact)
        except Exception:
            pass
        try:
            self.publish_artifact_created(artifact)
        except Exception:
            pass
        return artifact

    def update_artifact_content(self, artifact_id: str, content: str, encoding: str = 'utf-8'):
        if content is None:
            raise ValueError('content is required')
        artifact = self.get_artifact_by_id(artifact_id)
        if not artifact:
            raise FileNotFoundError('Artifact not found')
        file_path = artifact.get('saved_path', '')
        if not file_path or not os.path.isfile(file_path):
            raise FileNotFoundError('Artifact file not found')
        preview_type = self.artifact_service.guess_preview_type(artifact.get('original_name', ''))
        if preview_type != 'text':
            raise ValueError('Only text files can be edited')
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
        except UnicodeEncodeError:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            encoding = 'utf-8'
        file_size = os.path.getsize(file_path)
        meta_path = artifact.get('_meta_path', '')
        if meta_path and os.path.isfile(meta_path):
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                meta['size'] = file_size
                meta['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with open(meta_path, 'w', encoding='utf-8') as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        return {'artifact_id': artifact_id, 'size': file_size, 'encoding': encoding, 'message': 'File updated successfully'}
