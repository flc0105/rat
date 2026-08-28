from flask import Blueprint, request

from server.web.api_response import WebApiResponder


def create_toolbar_preferences_blueprint(server_instance):
    blueprint = Blueprint('toolbar_preferences', __name__)
    toolbar_api = server_instance.web_service.toolbar_preferences_api
    responder = WebApiResponder()

    @blueprint.get('/api/toolbar/preferences')
    def get_toolbar_preferences():
        return responder.json_endpoint(
            toolbar_api.get_preferences,
            default_error_status=500,
        )

    @blueprint.put('/api/toolbar/preferences')
    def save_toolbar_preferences():
        return responder.json_endpoint(
            lambda: toolbar_api.save_preferences(request.get_json(silent=True) or {}),
            default_error_status=500,
        )

    return blueprint
