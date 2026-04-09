from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_quick_jump_blueprint(server_instance):
    blueprint = Blueprint('quick_jumps', __name__)
    web_service = server_instance.web_service
    quick_jump_api = web_service.quick_jump_api
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/quick-jumps')
    def list_quick_jumps(client_id):
        return responder.json_endpoint(
            lambda: quick_jump_api.list_quick_jumps(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/quick-jumps')
    def save_quick_jump(client_id):
        def _execute():
            payload = get_json_payload()
            display_name = (payload.get('display_name') or '').strip()
            path = (payload.get('path') or '').strip()

            if not display_name:
                raise ValueError('display_name is required')
            if not path:
                raise ValueError('path is required')

            return quick_jump_api.save_quick_jump(client_id, display_name, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.put('/api/connections/<client_id>/quick-jumps')
    def update_quick_jump(client_id):
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

            return quick_jump_api.update_quick_jump(client_id, original_display_name, display_name, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>/quick-jumps')
    def delete_quick_jump(client_id):
        def _execute():
            payload = get_json_payload()
            display_name = (payload.get('display_name') or '').strip()
            if not display_name:
                raise ValueError('display_name is required')
            return quick_jump_api.delete_quick_jump(client_id, display_name)

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
