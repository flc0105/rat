import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import (
    get_optional_tab_id,
    get_required_command,
    get_required_upload,
)


def create_command_execution_blueprint(server_instance):
    blueprint = Blueprint('command_execution', __name__)
    web_service = server_instance.web_service
    command_execution_api = web_service.command_execution_api
    command_catalog_api = web_service.command_catalog_api
    artifact_api = web_service.artifact_api
    responder = WebApiResponder()

    @blueprint.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        def _execute():
            return command_execution_api.submit_web_command(
                client_id,
                get_required_command(),
                tab_id=get_optional_tab_id(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/tasks/<task_id>/cancel')
    def cancel_task(task_id):
        return responder.json_endpoint(
            lambda: command_execution_api.cancel_web_task(task_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/command-candidates')
    def get_command_candidates(client_id):
        return responder.json_endpoint(
            lambda: command_catalog_api.get_command_candidates(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        def _execute():
            upload = get_required_upload()
            target_path = (request.form.get('target_path') or '').strip()

            temp_path, safe_name = artifact_api.create_upload_temp_file(upload)
            return command_execution_api.submit_web_upload(
                client_id,
                temp_path,
                safe_name,
                target_path,
                tab_id=get_optional_tab_id(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/upload-tmp/<temp_id>/<filename>')
    @allow_anonymous
    def download_upload_tmp_file(temp_id, filename):
        try:
            file_path = artifact_api.get_upload_temp_file_path(temp_id, filename)
            return send_file(
                file_path,
                as_attachment=True,
                download_name=os.path.basename(file_path),
            )
        except Exception as e:
            return responder.map_common_error(e)

    return blueprint