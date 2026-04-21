import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
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
    artifact_api = web_service.artifact_api
    responder = WebApiResponder()

    @blueprint.get('/api/artifacts')
    def get_artifacts():
        artifact_type = (request.args.get('type') or '').strip()
        machine_id = (request.args.get('machine_id') or '').strip()
        return responder.json_endpoint(
            lambda: artifact_api.list_artifacts(artifact_type=artifact_type, machine_id=machine_id),
            default_error_status=500,
        )

    @blueprint.get('/api/artifacts/<artifact_id>/download')
    def download_artifact(artifact_id):
        try:
            artifact = artifact_api.get_artifact_by_id(artifact_id)
            file_path = artifact_api.get_artifact_file_path(artifact_id)
            download_name = artifact.get('original_name') or artifact.get('stored_name') or os.path.basename(file_path)
            return send_file(file_path, as_attachment=True, download_name=download_name)
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/artifacts/<artifact_id>/raw')
    def raw_artifact(artifact_id):
        try:
            file_path = artifact_api.get_artifact_file_path(artifact_id)
            return send_file(file_path, as_attachment=False)
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/artifacts/<artifact_id>/preview')
    def preview_artifact(artifact_id):
        return responder.file_endpoint(lambda: artifact_api.build_artifact_preview_payload(artifact_id))

    @blueprint.delete('/api/artifacts/<artifact_id>')
    def delete_artifact(artifact_id):
        return responder.file_endpoint(lambda: artifact_api.delete_artifact(artifact_id))

    @blueprint.post('/api/artifacts/clear')
    def clear_artifacts():
        def _execute():
            payload = get_json_payload()
            artifact_type = (payload.get('type') or '').strip()
            machine_id = (payload.get('machine_id') or '').strip()
            if not artifact_type:
                raise ValueError('type is required')
            return artifact_api.clear_artifacts(artifact_type, machine_id=machine_id)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/files/upload')
    @allow_anonymous
    def upload_file():
        def _execute():
            upload = get_required_upload()
            artifact_type = get_optional_form_text('artifact_type', 'files')
            category = get_optional_form_text('category', '')
            client_id = get_optional_form_text('client_id', '')
            hostname = get_optional_form_text('hostname', '')
            machine_id = get_optional_form_text('machine_id', '')
            job_id = get_optional_form_text('job_id', '')
            job_name = get_optional_form_text('job_name', '')
            job_key = get_optional_form_text('job_key', '')
            source_type = get_optional_form_text('source_type', 'client_upload')
            related_path = get_optional_form_text('related_path', '')
            source_command_id = parse_optional_int_form('source_command_id')
            extra = parse_optional_json_form('extra')
            return artifact_api.save_http_uploaded_file(
                upload,
                artifact_type=artifact_type,
                category=category,
                client_id=client_id,
                hostname=hostname,
                machine_id=machine_id,
                job_id=job_id,
                job_name=job_name,
                job_key=job_key,
                source_type=source_type,
                related_path=related_path,
                source_command_id=source_command_id,
                extra=extra,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.put('/api/artifacts/<artifact_id>/content')
    def update_artifact_content(artifact_id):
        def _execute():
            payload = get_json_payload()
            content = payload.get('content', '')
            encoding = (payload.get('encoding') or 'utf-8').strip()
            return artifact_api.update_artifact_content(artifact_id=artifact_id, content=content, encoding=encoding)
        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
