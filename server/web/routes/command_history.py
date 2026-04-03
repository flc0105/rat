from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_command_history_blueprint(server_instance):
    blueprint = Blueprint('command_history', __name__)
    web_service = server_instance.web_service
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/command-history')
    def get_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.get_command_history(client_id),
            default_error_status=500
        )

    @blueprint.get('/api/connections/<client_id>/command-history/full')
    def get_full_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.get_command_execution_history(client_id),
            default_error_status=500
        )

    @blueprint.delete('/api/connections/<client_id>/command-history')
    def clear_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.clear_command_history(client_id),
            default_error_status=500
        )

    @blueprint.post('/api/connections/<client_id>/command-history/pin')
    def set_command_history_pinned(client_id):
        def _execute():
            payload = get_json_payload()
            command = (payload.get('command') or '').strip()
            if not command:
                raise ValueError('command is required')

            return web_service.set_command_history_pinned(
                client_id,
                command,
                payload.get('is_pinned', False)
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/command-history/pin/move')
    def move_command_history_pinned(client_id):
        def _execute():
            payload = get_json_payload()
            command = (payload.get('command') or '').strip()
            direction = (payload.get('direction') or '').strip().lower()

            if not command:
                raise ValueError('command is required')
            if direction not in ('up', 'down'):
                raise ValueError('direction must be up or down')

            return web_service.move_command_history_pinned(
                client_id,
                command,
                direction,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>/command-history/full/<entry_id>')
    def delete_command_execution_history_entry(client_id, entry_id):
        return responder.json_endpoint(
            lambda: web_service.delete_command_execution_history_entry(client_id, entry_id),
            default_error_status=500
        )

    return blueprint