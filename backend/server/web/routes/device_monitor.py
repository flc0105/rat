from flask import Blueprint, request

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_device_monitor_blueprint(server_instance):
    blueprint = Blueprint('device_monitor', __name__)
    device_monitor_api = server_instance.web_service.device_monitor_api
    responder = WebApiResponder()

    def _tab_id():
        value = str(request.headers.get('X-Tab-Id') or '').strip()
        if not value:
            raise ValueError('X-Tab-Id is required')
        return value

    @blueprint.post('/api/connections/<client_id>/device-monitor/open')
    def open_device_monitor(client_id):
        def _execute():
            payload = get_json_payload()
            return device_monitor_api.open_monitor(
                client_id,
                _tab_id(),
                channels=payload.get('channels'),
                intervals=payload.get('intervals'),
                options=payload.get('options'),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/device-monitor/<monitor_session_id>/config')
    def update_device_monitor(monitor_session_id):
        def _execute():
            payload = get_json_payload()
            return device_monitor_api.update_monitor(
                monitor_session_id,
                _tab_id(),
                channels=payload.get('channels'),
                intervals=payload.get('intervals'),
                options=payload.get('options'),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/device-monitor/<monitor_session_id>/close')
    def close_device_monitor(monitor_session_id):
        return responder.json_endpoint(
            lambda: device_monitor_api.close_monitor(monitor_session_id, _tab_id()),
            default_error_status=500,
        )

    return blueprint
