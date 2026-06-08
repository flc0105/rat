from flask import Blueprint, request

from server.web.api_response import WebApiResponder


def create_connections_blueprint(server_instance):
    blueprint = Blueprint('connections', __name__)
    connection_api = server_instance.web_service.connection_api
    responder = WebApiResponder()

    @blueprint.get('/api/connections')
    def get_connections():
        return responder.ok(connection_api.get_connections_payload())

    @blueprint.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.patch('/api/connections/device-view-prefs')
    def update_connection_device_view_prefs():
        def _execute():
            body = request.get_json(silent=True) or {}
            client_id = str(body.get('client_id') or '').strip()
            machine_id = str(body.get('machine_id') or '').strip()
            patch = {}

            if 'machine_alias' in body:
                patch['machine_alias'] = body.get('machine_alias')
            if 'client_hidden' in body:
                patch['client_hidden'] = bool(body.get('client_hidden'))
            if 'machine_hidden' in body:
                patch['machine_hidden'] = bool(body.get('machine_hidden'))

            return connection_api.update_connection_device_view_prefs(
                client_id=client_id,
                machine_id=machine_id,
                patch=patch,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>')
    def remove_connection(client_id):
        def _execute():
            body = request.get_json(silent=True) or {}
            machine_id = str(body.get('machine_id') or '').strip()
            return connection_api.remove_connection(client_id, machine_id=machine_id)

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint