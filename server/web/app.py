import json
import os
import queue
from datetime import datetime

from flask import Flask, Response, request, send_file, send_from_directory, stream_with_context

from server.config.config import WEB_HTTP_UPLOAD_MAX_BYTES
from server.web.api_response import WebApiResponder
from server.web.request_parsers import (
    get_optional_tab_id,
    get_required_command,
    get_required_upload,
)
from server.web.routes.agent import create_agent_blueprint
from server.web.routes.artifacts import create_artifacts_blueprint
from server.web.routes.background_jobs import create_background_job_blueprint
from server.web.routes.command_history import create_command_history_blueprint
from server.web.routes.pinned_paths import create_pinned_path_blueprint
from server.web.routes.remote_files import create_remote_files_blueprint
from server.web.routes.system_inspection import create_system_inspection_blueprint
from server.application.connection.control_command_store import ControlCommandStore

def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')

    web_service = server_instance.web_service
    connection_api = web_service.connection_api
    command_api = web_service.command_api
    artifact_api = web_service.artifact_api
    responder = WebApiResponder()
    control_command_store = ControlCommandStore()

    app.register_blueprint(create_background_job_blueprint(server_instance))
    app.register_blueprint(create_remote_files_blueprint(server_instance))
    app.register_blueprint(create_pinned_path_blueprint(server_instance))
    app.register_blueprint(create_system_inspection_blueprint(server_instance))
    app.register_blueprint(create_command_history_blueprint(server_instance))
    app.register_blueprint(create_artifacts_blueprint(server_instance))
    app.register_blueprint(create_agent_blueprint(server_instance))
    app.config['MAX_CONTENT_LENGTH'] = WEB_HTTP_UPLOAD_MAX_BYTES

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/connections')
    def get_connections():
        return responder.ok(connection_api.get_connections_payload())

    @app.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        def _execute():
            return command_api.submit_web_command(
                client_id,
                get_required_command(),
                tab_id=get_optional_tab_id(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/tasks/<task_id>/cancel')
    def cancel_task(task_id):
        return responder.json_endpoint(
            lambda: command_api.cancel_web_task(task_id),
            default_error_status=500,
        )

    @app.get('/api/connections/<client_id>/command-candidates')
    def get_command_candidates(client_id):
        return responder.json_endpoint(
            lambda: command_api.get_command_candidates(client_id),
            default_error_status=500,
        )

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.route('/api/connections/<client_id>/control', methods=['GET', 'POST'])
    def connection_control(client_id):
        def _execute():
            if request.method == 'POST':
                payload = request.get_json(silent=True) or {}
                command = str(payload.get('command') or '').strip().lower()

                if command not in ('kill', 'reset', 'spawn'):
                    raise ValueError('command must be kill, reset or spawn')

                server_instance.get_target_connection_by_client_id(client_id)
                return control_command_store.set_pending_command(client_id, command)

            data = control_command_store.pop_pending_command(client_id)
            if data is None:
                return {'command': ''}

            return data

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        def _execute():
            upload = get_required_upload()
            target_path = (request.form.get('target_path') or '').strip()

            temp_path, safe_name = artifact_api.create_upload_temp_file(upload)
            return command_api.submit_web_upload(
                client_id,
                temp_path,
                safe_name,
                target_path,
                tab_id=get_optional_tab_id(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.get('/api/upload-tmp/<temp_id>/<filename>')
    def download_upload_tmp_file(temp_id, filename):
        try:
            file_path = artifact_api.get_upload_temp_file_path(temp_id, filename)
            return send_file(
                file_path,
                as_attachment=True,
                download_name=os.path.basename(file_path),
            )
        except Exception as e:
            return responder.map_common_error(e)

    @app.get('/api/stream')
    def stream():
        tab_id = (request.args.get('tab_id') or '').strip()
        q = web_service.event_bus.subscribe(tab_id=tab_id)

        def event_stream():
            try:
                while True:
                    try:
                        item = q.get(timeout=15)
                        yield f"event: {item['event']}\n"
                        yield f"data: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
                    except queue.Empty:
                        yield 'event: ping\n'
                        yield f"data: {json.dumps({'time': datetime.now().isoformat()}, ensure_ascii=False)}\n\n"
            finally:
                web_service.event_bus.unsubscribe(q)

        return Response(
            stream_with_context(event_stream()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
            },
        )

    @app.errorhandler(413)
    def file_too_large(_):
        return responder.fail('File is too large', 413)

    return app