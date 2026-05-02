from flask import Blueprint, request

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import get_json_payload


def create_keychain_blueprint(server_instance):
    blueprint = Blueprint('keychains', __name__)
    keychain_api = server_instance.web_service.keychain_api
    responder = WebApiResponder()

    @blueprint.get('/api/keychains')
    def list_keychains():
        machine_id = (request.args.get('machine_id') or '').strip()
        return responder.json_endpoint(
            lambda: keychain_api.list_keychains(machine_id=machine_id),
            default_error_status=500,
        )

    @blueprint.post('/api/keychains/resolve')
    @allow_anonymous
    def resolve_keychain_item():
        return responder.json_endpoint(
            lambda: keychain_api.resolve_keychain_item(get_json_payload()),
            default_error_status=500,
        )

    @blueprint.get('/api/keychains/<cred_id>')
    def get_keychain_item(cred_id):
        return responder.json_endpoint(
            lambda: keychain_api.get_keychain_item(cred_id),
            default_error_status=500,
        )

    @blueprint.post('/api/keychains')
    def create_keychain_item():
        return responder.json_endpoint(
            lambda: keychain_api.create_keychain_item(get_json_payload()),
            default_error_status=500,
        )

    @blueprint.put('/api/keychains/<cred_id>')
    def update_keychain_item(cred_id):
        return responder.json_endpoint(
            lambda: keychain_api.update_keychain_item(cred_id, get_json_payload()),
            default_error_status=500,
        )

    @blueprint.delete('/api/keychains/<cred_id>')
    def delete_keychain_item(cred_id):
        return responder.json_endpoint(
            lambda: keychain_api.delete_keychain_item(cred_id),
            default_error_status=500,
        )

    return blueprint
