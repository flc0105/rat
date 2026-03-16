import json
import os
import queue
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/connections')
    def get_connections():
        return jsonify({
            'code': 0,
            'data': server_instance.get_connections_payload()
        })

    @app.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        payload = request.get_json(silent=True) or {}
        command = (payload.get('command') or '').strip()

        if not command:
            return jsonify({
                'code': 1,
                'message': 'command is required'
            }), 400

        try:
            result = server_instance.submit_web_command(client_id, command)
            return jsonify({
                'code': 0,
                'message': 'ok',
                'data': result
            })
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 400

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        try:
            server_instance.kill_connection_by_client_id(client_id)
            return jsonify({
                'code': 0,
                'message': 'ok'
            })
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 400

    @app.get('/api/stream')
    def stream():
        q = server_instance.event_bus.subscribe()

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
                server_instance.event_bus.unsubscribe(q)

        return Response(
            stream_with_context(event_stream()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    #web files
    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        upload = request.files.get('file')
        if not upload or not upload.filename:
            return jsonify({
                'code': 1,
                'message': 'file is required'
            }), 400

        try:
            safe_name = secure_filename(upload.filename) or 'upload.bin'
            temp_dir = os.path.join(server_instance.upload_tmp_dir, uuid.uuid4().hex)
            os.makedirs(temp_dir, exist_ok=True)

            temp_path = os.path.join(temp_dir, safe_name)
            upload.save(temp_path)

            result = server_instance.submit_web_upload(client_id, temp_path, safe_name)
            return jsonify({
                'code': 0,
                'message': 'ok',
                'data': result
            })
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 400

    @app.get('/api/files/recent')
    def get_recent_files():
        items = []
        for item in server_instance.list_recent_received_files():
            items.append({
                'client_id': item['client_id'],
                'original_name': item['original_name'],
                'saved_name': item['saved_name'],
                'size': item['size'],
                'created_at': item['created_at'],
                'download_url': f"/api/files/recent/{item['saved_name']}"
            })

        return jsonify({
            'code': 0,
            'data': items
        })

    @app.get('/api/files/recent/<path:saved_name>')
    def download_recent_file(saved_name):
        item = server_instance.get_received_file_item(saved_name)
        if not item:
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404

        return send_from_directory(
            server_instance.received_files_dir,
            item['saved_name'],
            as_attachment=True,
            download_name=item['original_name']
        )

    return app

