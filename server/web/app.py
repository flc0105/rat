import json
import os
import queue
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_file, send_from_directory, stream_with_context

from server.config.config import WEB_HTTP_UPLOAD_MAX_BYTES
from server.web.routes.background_jobs import create_background_job_blueprint


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')

    web_service = server_instance.web_service
    artifact_service = web_service.artifact_service

    app.register_blueprint(create_background_job_blueprint(server_instance))
    app.config['MAX_CONTENT_LENGTH'] = WEB_HTTP_UPLOAD_MAX_BYTES

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

    def _map_common_error(error):
        if isinstance(error, ValueError):
            return _fail(str(error), 400)
        if isinstance(error, FileNotFoundError):
            return _fail('file not found', 404)
        return _fail(str(error), 500)

    def _json_endpoint(func, *, default_error_status=400):
        try:
            return _ok(func())
        except ValueError as e:
            return _fail(e, 400)
        except FileNotFoundError as e:
            return _fail(e, 404)
        except Exception as e:
            return _fail(e, default_error_status)

    def _file_endpoint(func):
        try:
            return _ok(func())
        except Exception as e:
            return _map_common_error(e)

    # ------------------ request helpers ------------------ #
    def _get_json_payload():
        return request.get_json(silent=True) or {}

    def _get_required_command():
        payload = _get_json_payload()
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

    def _get_optional_form_text(name: str, default: str = '') -> str:
        return (request.form.get(name) or default).strip()

    def _parse_optional_json_form(name: str) -> dict:
        raw = (request.form.get(name) or '').strip()
        if not raw:
            return {}

        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass

        return {}

    def _parse_optional_int_form(name: str):
        raw = (request.form.get(name) or '').strip()
        if not raw:
            return None

        try:
            return int(raw)
        except Exception:
            return None

    def _resolve_client_context(client_id: str) -> tuple[str, str]:
        hostname = ''
        addr = ''

        if not client_id:
            return hostname, addr

        try:
            conn = server_instance.get_target_connection_by_client_id(client_id)
            conn_info = getattr(conn, 'info', {}) or {}
            hostname = conn_info.get('hostname', '') or ''
            addr = conn_info.get('addr', '') or ''
        except Exception:
            pass

        return hostname, addr

    def _bind_uploaded_artifact_to_history(client_id: str, source_command_id, artifact: dict):
        if not client_id or source_command_id is None:
            return

        try:
            conn = server_instance.get_target_connection_by_client_id(client_id)
            entry_id = conn.get_history_entry_id(source_command_id)
            if not entry_id:
                return

            server_instance.command_history.append_file_for_connection(
                conn,
                entry_id,
                artifact
            )
        except Exception:
            pass

    def _publish_artifact_created(artifact: dict):
        try:
            web_service.publish_artifact_created(artifact)
        except Exception:
            pass

    # ------------------ static / index ------------------ #
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
            lambda: web_service.submit_command(client_id, _get_required_command()),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-candidates')
    def get_command_candidates(client_id):
        return _json_endpoint(
            lambda: web_service.get_command_candidates(client_id),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-history')
    def get_command_history(client_id):
        return _json_endpoint(
            lambda: web_service.get_command_history(client_id),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-history/full')
    def get_full_command_history(client_id):
        return _json_endpoint(
            lambda: web_service.get_command_execution_history(client_id),
            default_error_status=500
        )

    @app.delete('/api/connections/<client_id>/command-history')
    def clear_command_history(client_id):
        return _json_endpoint(
            lambda: web_service.clear_command_history(client_id),
            default_error_status=500
        )

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return _json_endpoint(_execute, default_error_status=500)

    # ------------------ web upload -> client ------------------ #
    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        def _execute():
            upload = _get_required_upload()
            target_path = (request.form.get('target_path') or '').strip()

            temp_path, safe_name = artifact_service.create_upload_temp_file(upload)
            return web_service.submit_upload(
                client_id,
                temp_path,
                safe_name,
                target_path
            )

        return _json_endpoint(_execute, default_error_status=500)

    # 关键：给 client 拉取 upload_tmp 文件用
    @app.get('/api/upload-tmp/<temp_id>/<filename>')
    def download_upload_tmp_file(temp_id, filename):
        try:
            file_path = artifact_service.get_upload_temp_file_path(temp_id, filename)
            return send_file(
                file_path,
                as_attachment=True,
                download_name=os.path.basename(file_path)
            )
        except Exception as e:
            return _map_common_error(e)

    # ------------------ remote files ------------------ #
    @app.get('/api/connections/<client_id>/remote-files')
    def browse_remote_files(client_id):
        return _json_endpoint(
            lambda: web_service.browse_remote_directory(client_id, _get_optional_remote_path()),
            default_error_status=500
        )

    @app.post('/api/connections/<client_id>/remote-files/mkdir')
    def create_remote_directory(client_id):
        def _execute():
            payload = _get_json_payload()
            path = (payload.get('path') or '').strip()
            if not path:
                raise ValueError('path is required')
            return web_service.create_remote_directory(client_id, path)

        return _json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/remote-files/rename')
    def rename_remote_path(client_id):
        def _execute():
            payload = _get_json_payload()
            old_path = (payload.get('old_path') or '').strip()
            new_name = (payload.get('new_name') or '').strip()

            if not old_path:
                raise ValueError('old_path is required')
            if not new_name:
                raise ValueError('new_name is required')

            return web_service.rename_remote_path(client_id, old_path, new_name)

        return _json_endpoint(_execute, default_error_status=500)

    @app.delete('/api/connections/<client_id>/remote-files')
    def delete_remote_file_or_directory(client_id):
        def _execute():
            path = _get_optional_remote_path()
            if not path:
                raise ValueError('path is required')
            return web_service.delete_remote_path(client_id, path)

        return _json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/remote-files/download')
    def download_remote_file(client_id):
        def _execute():
            path = _get_optional_remote_path()
            if not path:
                raise ValueError('path is required')
            return web_service.download_remote_file(client_id, path)

        return _json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/remote-files/download-zip')
    def download_remote_paths_as_zip(client_id):
        def _execute():
            payload = _get_json_payload()
            paths = payload.get('paths') or []
            archive_name = (payload.get('archive_name') or '').strip()

            if not isinstance(paths, list) or not paths:
                raise ValueError('paths is required')

            return web_service.download_remote_paths_as_zip(client_id, paths, archive_name)

        return _json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/remote-files/preview')
    def preview_remote_file(client_id):
        def _execute():
            payload = _get_json_payload()
            path = (payload.get('path') or '').strip()
            if not path:
                raise ValueError('path is required')
            return web_service.preview_remote_file(client_id, path)

        return _json_endpoint(_execute, default_error_status=500)

    # ------------------ SSE ------------------ #
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
            }
        )

    # ------------------ artifacts ------------------ #
    @app.get('/api/artifacts')
    def get_artifacts():
        artifact_type = (request.args.get('type') or '').strip()
        hostname = (request.args.get('hostname') or '').strip()

        return _json_endpoint(
            lambda: web_service.list_artifacts(
                artifact_type=artifact_type,
                hostname=hostname
            ),
            default_error_status=500
        )

    @app.get('/api/artifacts/<artifact_id>/download')
    def download_artifact(artifact_id):
        try:
            artifact = web_service.get_artifact_by_id(artifact_id)
            file_path = web_service.get_artifact_file_path(artifact_id)
            download_name = (
                artifact.get('original_name')
                or artifact.get('stored_name')
                or os.path.basename(file_path)
            )
            return send_file(file_path, as_attachment=True, download_name=download_name)
        except Exception as e:
            return _map_common_error(e)

    @app.get('/api/artifacts/<artifact_id>/raw')
    def raw_artifact(artifact_id):
        try:
            file_path = web_service.get_artifact_file_path(artifact_id)
            return send_file(file_path, as_attachment=False)
        except Exception as e:
            return _map_common_error(e)

    @app.get('/api/artifacts/<artifact_id>/preview')
    def preview_artifact(artifact_id):
        return _file_endpoint(
            lambda: web_service.build_artifact_preview_payload(artifact_id)
        )

    @app.delete('/api/artifacts/<artifact_id>')
    def delete_artifact(artifact_id):
        return _file_endpoint(
            lambda: web_service.delete_artifact(artifact_id)
        )

    @app.post('/api/artifacts/clear')
    def clear_artifacts():
        def _execute():
            payload = _get_json_payload()
            artifact_type = (payload.get('type') or '').strip()
            hostname = (payload.get('hostname') or '').strip()

            if not artifact_type:
                raise ValueError('type is required')

            return web_service.clear_artifacts(artifact_type, hostname=hostname)

        return _json_endpoint(_execute, default_error_status=500)

    # ------------------ client/job http upload -> artifact ------------------ #
    @app.post('/api/files/upload')
    def upload_file():
        def _execute():
            upload = _get_required_upload()

            artifact_type = _get_optional_form_text('artifact_type', 'files')
            category = _get_optional_form_text('category', '')
            client_id = _get_optional_form_text('client_id', '')
            hostname = _get_optional_form_text('hostname', '')
            job_id = _get_optional_form_text('job_id', '')
            job_name = _get_optional_form_text('job_name', '')
            job_key = _get_optional_form_text('job_key', '')
            source_type = _get_optional_form_text('source_type', 'client_upload')
            related_path = _get_optional_form_text('related_path', '')
            source_command_id = _parse_optional_int_form('source_command_id')
            extra = _parse_optional_json_form('extra')

            resolved_hostname, addr = _resolve_client_context(client_id)
            hostname = hostname or resolved_hostname

            artifact = artifact_service.save_http_uploaded_file(
                upload,
                artifact_type=artifact_type,
                category=category,
                client_id=client_id,
                hostname=hostname,
                job_id=job_id,
                job_name=job_name,
                job_key=job_key,
                source_type=source_type,
                source_command_id=source_command_id,
                addr=addr,
                related_path=related_path,
                extra=extra,
            )

            _bind_uploaded_artifact_to_history(client_id, source_command_id, artifact)
            _publish_artifact_created(artifact)

            return artifact

        return _json_endpoint(_execute, default_error_status=500)

    # ------------------ errors ------------------ #
    @app.errorhandler(413)
    def file_too_large(_):
        return _fail('File is too large', 413)

    return app