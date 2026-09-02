from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_optional_tab_id


def create_transfers_blueprint(server_instance):
    blueprint = Blueprint('transfers', __name__)
    transfer_api = server_instance.web_service.transfer_api
    responder = WebApiResponder()

    @blueprint.get('/api/transfers')
    def list_transfers():
        return responder.json_endpoint(
            lambda: transfer_api.list_transfers(tab_id=get_optional_tab_id()),
            default_error_status=500,
        )

    return blueprint
