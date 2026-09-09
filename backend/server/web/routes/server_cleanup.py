import os

from flask import Blueprint, send_file

from server.web.api_response import WebApiResponder


def create_server_cleanup_blueprint(server_instance):
    blueprint = Blueprint('server_cleanup', __name__)
    cleanup_api = server_instance.web_service.server_cleanup_api
    responder = WebApiResponder()

    @blueprint.get('/api/server-cleanup/runs/<run_id>/log')
    def get_cleanup_log(run_id):
        try:
            file_path = cleanup_api.get_log_path(run_id)
            return send_file(
                file_path,
                as_attachment=False,
                download_name=os.path.basename(file_path),
                mimetype='text/plain',
            )
        except Exception as exc:
            return responder.map_common_error(exc)

    return blueprint
