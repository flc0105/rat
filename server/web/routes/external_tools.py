import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import get_json_payload, get_optional_tab_id


def create_external_tool_blueprint(server_instance):
    blueprint = Blueprint('external_tools', __name__)
    web_service = server_instance.web_service
    external_tool_api = web_service.external_tool_api
    responder = WebApiResponder()

    @blueprint.get('/api/external-tools/catalog')
    def list_external_tools():
        return responder.json_endpoint(
            lambda: external_tool_api.list_catalog(),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>')
    def get_external_tool(tool_id):
        return responder.json_endpoint(
            lambda: external_tool_api.get_tool(tool_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>/download')
    def download_external_tool_by_id(tool_id):
        try:
            meta = external_tool_api.get_tool(tool_id)
            filename = str((meta.get('package') or {}).get('filename') or '').strip()
            if not filename:
                raise ValueError('package.filename is required')
            file_path = external_tool_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/external-tools/packages/<filename>')
    @allow_anonymous
    def download_external_tool_package(filename):
        try:
            file_path = external_tool_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.post('/api/external-tools/<tool_id>/server/run')
    def install_and_run_server_tool(tool_id):
        def _execute():
            payload = get_json_payload()
            params = payload.get('params') or {}
            if not isinstance(params, dict):
                raise ValueError('params must be an object')
            return external_tool_api.install_and_run_server(tool_id, params=params)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/run')
    def install_and_run_client_tool(client_id, tool_id):
        def _execute():
            payload = get_json_payload()
            params = payload.get('params') or {}
            if not isinstance(params, dict):
                raise ValueError('params must be an object')
            return external_tool_api.install_and_run_client(
                client_id,
                tool_id,
                params=params,
                tab_id=get_optional_tab_id(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
