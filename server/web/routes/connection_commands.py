import json
import os
import queue
from datetime import datetime

from flask import Blueprint, Response, request, send_file, stream_with_context

from server.application.connection.control_command_store import ControlCommandStore
from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import (
    get_optional_tab_id,
    get_required_command,
    get_required_upload,
)


def create_connection_command_blueprint(server_instance):
    blueprint = Blueprint('connection_commands', __name__)
    web_service = server_instance.web_service
    connection_api = web_service.connection_api
    command_api = web_service.command_api
    artifact_api = web_service.artifact_api
    responder = WebApiResponder()
    control_command_store = ControlCommandStore()

    @blueprint.get('/api/connections')
    def get_connections():
        return responder.ok(connection_api.get_connections_payload())

    @blueprint.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        def _execute():
            return command_api.submit_web_command(
                client_id,
                get_required_command(),
                tab_id=get_optional_tab_id(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/tasks/<task_id>/cancel')
    def cancel_task(task_id):
        return responder.json_endpoint(
            lambda: command_api.cancel_web_task(task_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/command-candidates')
    def get_command_candidates(client_id):
        return responder.json_endpoint(
            lambda: command_api.get_command_candidates(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/control')
    @allow_anonymous
    def get_connection_control(client_id):
        return responder.json_endpoint(
            lambda: control_command_store.pop_pending_command(client_id) or {'command': ''},
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/control')
    def set_connection_control(client_id):
        def _execute():
            payload = request.get_json(silent=True) or {}
            command = str(payload.get('command') or '').strip().lower()

            if command not in ('kill', 'reset', 'spawn'):
                raise ValueError('command must be kill, reset or spawn')

            server_instance.get_target_connection_by_client_id(client_id)
            return control_command_store.set_pending_command(client_id, command)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/upload')
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

    @blueprint.get('/api/upload-tmp/<temp_id>/<filename>')
    @allow_anonymous
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

    @blueprint.get('/api/stream')
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

    return blueprint