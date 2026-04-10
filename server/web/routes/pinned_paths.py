from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_pinned_path_blueprint(server_instance):
    blueprint = Blueprint('pinned_paths', __name__)
    web_service = server_instance.web_service
    pinned_path_api = web_service.pinned_path_api
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/quick-jumps')
    def list_pinned_paths(client_id):
        return responder.json_endpoint(
            lambda: pinned_path_api.list_pinned_paths(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/quick-jumps')
    def save_pinned_paths(client_id):
        def _execute():
            payload = get_json_payload()
            display_name = (payload.get('display_name') or '').strip()
            path = (payload.get('path') or '').strip()

            if not display_name:
                raise ValueError('display_name is required')
            if not path:
                raise ValueError('path is required')

            return pinned_path_api.save_pinned_paths(client_id, display_name, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.put('/api/connections/<client_id>/quick-jumps')
    def update_pinned_path(client_id):
        def _execute():
            payload = get_json_payload()
            original_display_name = (payload.get('original_display_name') or '').strip()
            display_name = (payload.get('display_name') or '').strip()
            path = (payload.get('path') or '').strip()

            if not original_display_name:
                raise ValueError('original_display_name is required')
            if not display_name:
                raise ValueError('display_name is required')
            if not path:
                raise ValueError('path is required')

            return pinned_path_api.update_pinned_path(client_id, original_display_name, display_name, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>/quick-jumps')
    def delete_pinned_path(client_id):
        def _execute():
            payload = get_json_payload()
            display_name = (payload.get('display_name') or '').strip()
            if not display_name:
                raise ValueError('display_name is required')
            return pinned_path_api.delete_pinned_path(client_id, display_name)

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
