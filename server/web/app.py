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

    def _get_optional_remote_path():
        return (request.args.get('path') or '').strip()

    # ------------------ error mapping ------------------ #
    def _map_common_error(error):
        if isinstance(error, ValueError):
            return _fail(str(error), 400)
        if isinstance(error, FileNotFoundError):
            return _fail('file not found', 404)
        return _fail(str(error), 500)

    def _json_endpoint(func, *, default_error_status=400):
        """
        统一 JSON 接口包装：
        - 正常返回值自动包装为 _ok(...)
        - ValueError 按 400 返回
        - 其他异常按 default_error_status 返回
        """
        try:
            result = func()
            return _ok(result)
        except ValueError as e:
            return _fail(e, 400)
        except Exception as e:
            return _fail(e, default_error_status)

    def _file_endpoint(func):
        """
        统一文件相关 JSON 接口包装：
        - 正常返回值自动包装为 _ok(...)
        - 文件路径/不存在等异常自动映射
        """
        try:
            result = func()
            return _ok(result)
        except Exception as e:
            return _map_common_error(e)

    # ------------------ file send helpers ------------------ #
    def _send_download_file(saved_name: str):
        file_path = file_service.get_received_file_download_path(saved_name)

        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')

        return send_from_directory(
            file_service.received_files_dir,
            saved_name,
            as_attachment=True,
            download_name=saved_name
        )

    def _send_raw_file(saved_name: str):
        file_path = file_service.get_safe_received_file_path(saved_name)

        if not os.path.isfile(file_path):
            raise FileNotFoundError('file not found')

        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        return send_from_directory(directory, filename, as_attachment=False)

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
        return _json_endpoint(
            lambda: web_service.submit_command(client_id, _get_required_command())
        )

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return _json_endpoint(_execute)

    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        def _execute():
            upload = _get_required_upload()
            temp_path, safe_name = file_service.create_upload_temp_file(upload)
            return web_service.submit_upload(client_id, temp_path, safe_name)

        return _json_endpoint(_execute)

    # ------------------ remote files ------------------ #
    @app.get('/api/connections/<client_id>/remote-files')
    def browse_remote_files(client_id):
        return _json_endpoint(
            lambda: web_service.browse_remote_directory(client_id, _get_optional_remote_path()),
            default_error_status=500
        )

    @app.delete('/api/connections/<client_id>/remote-files')
    def delete_remote_file_or_directory(client_id):
        def _execute():
            path = _get_optional_remote_path()
            if not path:
                raise ValueError('path is required')
            return web_service.delete_remote_path(client_id, path)

        return _json_endpoint(_execute, default_error_status=500)

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
        return _json_endpoint(
            lambda: file_service.list_received_files(),
            default_error_status=500
        )

    @app.get('/api/files/recent/<path:saved_name>')
    def download_recent_file(saved_name):
        try:
            return _send_download_file(saved_name)
        except Exception as e:
            return _map_common_error(e)

    @app.get('/api/files/recent/<path:saved_name>/raw')
    def get_recent_file_raw(saved_name):
        try:
            return _send_raw_file(saved_name)
        except Exception as e:
            return _map_common_error(e)

    @app.get('/api/files/recent/<path:saved_name>/preview')
    def preview_recent_file(saved_name):
        return _file_endpoint(
            lambda: file_service.build_file_preview_payload(saved_name)
        )

    @app.delete('/api/files/recent/<path:saved_name>')
    def delete_recent_file(saved_name):
        def _execute():
            file_service.delete_received_file(saved_name)
            return None

        return _file_endpoint(_execute)

    # ------------------ http uploads ------------------ #
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

    @app.route('/api/files/upload', methods=['POST'])
    def upload_file():
        def _execute():
            upload = _get_required_upload()
            category = request.form.get('category', '').strip()
            client_id = request.form.get('client_id', '').strip()

            return file_service.save_http_uploaded_file(
                upload,
                category=category,
                client_id=client_id
            )

        return _json_endpoint(_execute, default_error_status=500)

    @app.errorhandler(413)
    def file_too_large(_):
        return _fail('File is too large', 413)

    return app