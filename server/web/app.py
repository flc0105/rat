import json
import os
import queue
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')
    web_service = server_instance.web_service
    file_service = web_service.file_service

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/connections')
    def get_connections():
        return jsonify({
            'code': 0,
            'data': web_service.get_connections_payload()
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
            result = web_service.submit_command(client_id, command)
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

    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        upload = request.files.get('file')
        if not upload or not upload.filename:
            return jsonify({
                'code': 1,
                'message': 'file is required'
            }), 400

        try:
            temp_path, safe_name = file_service.create_upload_temp_file(upload)
            result = web_service.submit_upload(client_id, temp_path, safe_name)
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
        return jsonify({
            'code': 0,
            'data': file_service.list_received_files()
        })

    @app.get('/api/files/recent/<path:saved_name>')
    def download_recent_file(saved_name):
        file_path = file_service.get_received_file_download_path(saved_name)

        if not os.path.isfile(file_path):
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404

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
        except ValueError:
            return jsonify({
                'code': 1,
                'message': 'invalid file path'
            }), 400

        if not os.path.isfile(file_path):
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404

        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        return send_from_directory(directory, filename, as_attachment=False)

    @app.get('/api/files/recent/<path:saved_name>/preview')
    def preview_recent_file(saved_name):
        try:
            payload = file_service.build_file_preview_payload(saved_name)
            return jsonify({
                'code': 0,
                'data': payload
            })
        except ValueError:
            return jsonify({
                'code': 1,
                'message': 'invalid file path'
            }), 400
        except FileNotFoundError:
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404

    @app.delete('/api/files/recent/<path:saved_name>')
    def delete_recent_file(saved_name):
        try:
            file_service.delete_received_file(saved_name)
        except ValueError:
            return jsonify({
                'code': 1,
                'message': 'invalid file path'
            }), 400
        except FileNotFoundError:
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 500

        return jsonify({
            'code': 0,
            'message': 'ok'
        })

    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

    @app.route('/api/files/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({
                'ok': False,
                'error': 'Missing file field: file'
            }), 400

        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({
                'ok': False,
                'error': 'No file selected'
            }), 400

        category = request.form.get('category', '').strip()
        client_id = request.form.get('client_id', '').strip()

        try:
            result = file_service.save_http_uploaded_file(file, category=category, client_id=client_id)
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'ok': False,
                'error': str(e)
            }), 500

    @app.errorhandler(413)
    def file_too_large(_):
        return jsonify({
            'ok': False,
            'error': 'File is too large'
        }), 413

    return app