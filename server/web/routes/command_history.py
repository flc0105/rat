from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_command_history_blueprint(server_instance):
    blueprint = Blueprint('command_history', __name__)
    web_service = server_instance.web_service
    command_api = web_service.command_api
    responder = WebApiResponder()

    @blueprint.get('/api/hosts/<hostname>/command-history')
    def get_command_history(hostname):
        return responder.json_endpoint(
            lambda: command_api.get_command_history(hostname),
            default_error_status=500,
        )

    @blueprint.get('/api/hosts/<hostname>/command-history/full')
    def get_full_command_history(hostname):
        return responder.json_endpoint(
            lambda: command_api.get_command_execution_history(hostname),
            default_error_status=500,
        )

    @blueprint.delete('/api/hosts/<hostname>/command-history')
    def clear_command_history(hostname):
        return responder.json_endpoint(
            lambda: command_api.clear_command_history(hostname),
            default_error_status=500,
        )

    @blueprint.post('/api/hosts/<hostname>/command-history/pin')
    def set_command_history_pinned(hostname):
        def _execute():
            payload = get_json_payload()
            command = (payload.get('command') or '').strip()
            if not command:
                raise ValueError('command is required')

            return command_api.set_command_history_pinned(
                hostname,
                command,
                payload.get('is_pinned', False),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/hosts/<hostname>/command-history/pin/move')
    def move_command_history_pinned(hostname):
        def _execute():
            payload = get_json_payload()
            command = (payload.get('command') or '').strip()
            direction = (payload.get('direction') or '').strip().lower()

            if not command:
                raise ValueError('command is required')
            if direction not in ('up', 'down'):
                raise ValueError('direction must be up or down')

            return command_api.move_command_history_pinned(
                hostname,
                command,
                direction,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/hosts/<hostname>/command-history/full/<entry_id>')
    def delete_command_execution_history_entry(hostname, entry_id):
        return responder.json_endpoint(
            lambda: command_api.delete_command_execution_history_entry(hostname, entry_id),
            default_error_status=500,
        )

    return blueprint
