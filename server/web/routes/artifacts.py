import json
import os
from datetime import datetime

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.request_parsers import (
    get_json_payload,
    get_optional_form_text,
    get_required_upload,
    parse_optional_int_form,
    parse_optional_json_form,
)


def create_artifacts_blueprint(server_instance):
    blueprint = Blueprint('artifacts', __name__)
    web_service = server_instance.web_service
    artifact_service = web_service.artifact_service
    responder = WebApiResponder()

    def _resolve_client_context(client_id: str) -> tuple[str, str]:
        hostname = ''
        addr = ''

        if not client_id:
            return hostname, addr

        try:
            conn = server_instance.get_target_connection_by_client_id(client_id)
            conn_info = getattr(conn, 'info', {}) or {}
            hostname = conn_info.get('hostname', '') or ''
            addr = conn_info.get('addr', '') or ''
        except Exception:
            pass

        return hostname, addr

    def _bind_uploaded_artifact_to_history(client_id: str, source_command_id, artifact: dict):
        try:
            web_service.bind_uploaded_artifact_to_history(
                client_id,
                source_command_id,
                artifact
            )
        except Exception:
            pass

    def _publish_artifact_created(artifact: dict):
        try:
            web_service.publish_artifact_created(artifact)
        except Exception:
            pass

    @blueprint.get('/api/artifacts')
    def get_artifacts():
        artifact_type = (request.args.get('type') or '').strip()
        hostname = (request.args.get('hostname') or '').strip()

        return responder.json_endpoint(
            lambda: web_service.list_artifacts(artifact_type=artifact_type, hostname=hostname),
            default_error_status=500
        )

    @blueprint.get('/api/artifacts/<artifact_id>/download')
    def download_artifact(artifact_id):
        try:
            artifact = web_service.get_artifact_by_id(artifact_id)
            file_path = web_service.get_artifact_file_path(artifact_id)
            download_name = (
                artifact.get('original_name')
                or artifact.get('stored_name')
                or os.path.basename(file_path)
            )
            return send_file(file_path, as_attachment=True, download_name=download_name)
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/artifacts/<artifact_id>/raw')
    def raw_artifact(artifact_id):
        try:
            file_path = web_service.get_artifact_file_path(artifact_id)
            return send_file(file_path, as_attachment=False)
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/artifacts/<artifact_id>/preview')
    def preview_artifact(artifact_id):
        return responder.file_endpoint(
            lambda: web_service.build_artifact_preview_payload(artifact_id)
        )

    @blueprint.delete('/api/artifacts/<artifact_id>')
    def delete_artifact(artifact_id):
        return responder.file_endpoint(
            lambda: web_service.delete_artifact(artifact_id)
        )

    @blueprint.post('/api/artifacts/clear')
    def clear_artifacts():
        def _execute():
            payload = get_json_payload()
            artifact_type = (payload.get('type') or '').strip()
            hostname = (payload.get('hostname') or '').strip()

            if not artifact_type:
                raise ValueError('type is required')

            return web_service.clear_artifacts(artifact_type, hostname=hostname)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/files/upload')
    def upload_file():
        def _execute():
            upload = get_required_upload()

            artifact_type = get_optional_form_text('artifact_type', 'files')
            category = get_optional_form_text('category', '')
            client_id = get_optional_form_text('client_id', '')
            hostname = get_optional_form_text('hostname', '')
            job_id = get_optional_form_text('job_id', '')
            job_name = get_optional_form_text('job_name', '')
            job_key = get_optional_form_text('job_key', '')
            source_type = get_optional_form_text('source_type', 'client_upload')
            related_path = get_optional_form_text('related_path', '')
            source_command_id = parse_optional_int_form('source_command_id')
            extra = parse_optional_json_form('extra')

            resolved_hostname, addr = _resolve_client_context(client_id)
            hostname = hostname or resolved_hostname

            artifact = artifact_service.save_http_uploaded_file(
                upload,
                artifact_type=artifact_type,
                category=category,
                client_id=client_id,
                hostname=hostname,
                job_id=job_id,
                job_name=job_name,
                job_key=job_key,
                source_type=source_type,
                source_command_id=source_command_id,
                addr=addr,
                related_path=related_path,
                extra=extra,
            )

            _bind_uploaded_artifact_to_history(client_id, source_command_id, artifact)
            _publish_artifact_created(artifact)

            return artifact

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.put('/api/artifacts/<artifact_id>/content')
    def update_artifact_content(artifact_id):
        """
        更新 Artifact 文件内容
        """

        def _execute():
            payload = get_json_payload()
            content = payload.get('content', '')
            encoding = (payload.get('encoding') or 'utf-8').strip()

            if content is None:
                raise ValueError('content is required')

            # 获取 artifact 信息
            artifact = web_service.get_artifact_by_id(artifact_id)
            if not artifact:
                raise FileNotFoundError('Artifact not found')

            file_path = artifact.get('saved_path', '')
            if not file_path or not os.path.isfile(file_path):
                raise FileNotFoundError('Artifact file not found')

            # 检查是否是文本文件（preview_type 为 text）
            preview_type = artifact_service.guess_preview_type(artifact.get('original_name', ''))
            if preview_type != 'text':
                raise ValueError('Only text files can be edited')

            # 写入新内容
            try:
                with open(file_path, 'w', encoding=encoding) as f:
                    f.write(content)
            except UnicodeEncodeError:
                # 如果指定编码失败，尝试 utf-8
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                encoding = 'utf-8'

            # 更新 artifact 元数据中的大小和修改时间
            file_size = os.path.getsize(file_path)

            # 更新 meta 文件
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

            return {
                'artifact_id': artifact_id,
                'size': file_size,
                'encoding': encoding,
                'message': 'File updated successfully'
            }

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint