from flask import Blueprint, request

from server.web.api_response import WebApiResponder


def create_notification_preferences_blueprint(server_instance):
    blueprint = Blueprint('notification_preferences', __name__)
    notification_api = server_instance.web_service.notification_preferences_api
    responder = WebApiResponder()

    @blueprint.get('/api/notifications/preferences')
    def get_notification_preferences():
        return responder.json_endpoint(
            notification_api.get_preferences,
            default_error_status=500,
        )

    @blueprint.put('/api/notifications/preferences')
    def save_notification_preferences():
        return responder.json_endpoint(
            lambda: notification_api.save_preferences(request.get_json(silent=True) or {}),
            default_error_status=500,
        )

    return blueprint
