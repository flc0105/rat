import json
import os
import queue
from datetime import datetime

from flask import Flask, Response, request, send_file, send_from_directory, stream_with_context

from server.config.config import WEB_HTTP_UPLOAD_MAX_BYTES
from server.web.api_response import WebApiResponder
from server.web.request_parsers import (
    get_json_payload,
    get_optional_form_text,
    get_optional_tab_id,
    get_required_command,
    get_required_upload,
    parse_optional_int_form,
    parse_optional_json_form,
)
from server.web.routes.background_jobs import create_background_job_blueprint
from server.web.routes.remote_files import create_remote_files_blueprint
from server.web.routes.system_inspection import create_system_inspection_blueprint


def create_app(server_instance):
    app = Flask(__name__, static_folder='../../static', static_url_path='')

    web_service = server_instance.web_service
    artifact_service = web_service.artifact_service
    responder = WebApiResponder()

    app.register_blueprint(create_background_job_blueprint(server_instance))
    app.register_blueprint(create_remote_files_blueprint(server_instance))
    app.register_blueprint(create_system_inspection_blueprint(server_instance))
    app.config['MAX_CONTENT_LENGTH'] = WEB_HTTP_UPLOAD_MAX_BYTES

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
        try:
            web_service.bind_uploaded_artifact_to_history(
                client_id,
                source_command_id,
                artifact
            )
        except Exception:
            pass

    def _publish_artifact_created(artifact: dict):
        try:
            web_service.publish_artifact_created(artifact)
        except Exception:
            pass

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/connections')
    def get_connections():
        return responder.ok(web_service.get_connections_payload())

    @app.post('/api/connections/<client_id>/command')
    def send_command(client_id):
        def _execute():
            return web_service.submit_command(
                client_id,
                get_required_command(),
                tab_id=get_optional_tab_id()
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/tasks/<task_id>/cancel')
    def cancel_task(task_id):
        return responder.json_endpoint(
            lambda: web_service.cancel_web_task(task_id),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-candidates')
    def get_command_candidates(client_id):
        return responder.json_endpoint(
            lambda: web_service.get_command_candidates(client_id),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-history')
    def get_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.get_command_history(client_id),
            default_error_status=500
        )

    @app.get('/api/connections/<client_id>/command-history/full')
    def get_full_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.get_command_execution_history(client_id),
            default_error_status=500
        )

    @app.delete('/api/connections/<client_id>/command-history')
    def clear_command_history(client_id):
        return responder.json_endpoint(
            lambda: web_service.clear_command_history(client_id),
            default_error_status=500
        )

    @app.post('/api/connections/<client_id>/command-history/pin')
    def set_command_history_pinned(client_id):
        def _execute():
            payload = get_json_payload()
            command = (payload.get('command') or '').strip()
            if not command:
                raise ValueError('command is required')

            return web_service.set_command_history_pinned(
                client_id,
                command,
                payload.get('is_pinned', False)
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.delete('/api/connections/<client_id>/command-history/full/<entry_id>')
    def delete_command_execution_history_entry(client_id, entry_id):
        return responder.json_endpoint(
            lambda: web_service.delete_command_execution_history_entry(client_id, entry_id),
            default_error_status=500
        )

    @app.post('/api/connections/<client_id>/kill')
    def kill_connection(client_id):
        def _execute():
            server_instance.kill_connection_by_client_id(client_id)
            return None

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/connections/<client_id>/upload')
    def upload_file_to_client(client_id):
        def _execute():
            upload = get_required_upload()
            target_path = (request.form.get('target_path') or '').strip()

            temp_path, safe_name = artifact_service.create_upload_temp_file(upload)
            return web_service.submit_upload(
                client_id,
                temp_path,
                safe_name,
                target_path,
                tab_id=get_optional_tab_id()
            )

        return responder.json_endpoint(_execute, default_error_status=500)

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
            }
        )

    @app.get('/api/artifacts')
    def get_artifacts():
        artifact_type = (request.args.get('type') or '').strip()
        hostname = (request.args.get('hostname') or '').strip()

        return responder.json_endpoint(
            lambda: web_service.list_artifacts(artifact_type=artifact_type, hostname=hostname),
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
            return responder.map_common_error(e)

    @app.get('/api/artifacts/<artifact_id>/raw')
    def raw_artifact(artifact_id):
        try:
            file_path = web_service.get_artifact_file_path(artifact_id)
            return send_file(file_path, as_attachment=False)
        except Exception as e:
            return responder.map_common_error(e)

    @app.get('/api/artifacts/<artifact_id>/preview')
    def preview_artifact(artifact_id):
        return responder.file_endpoint(
            lambda: web_service.build_artifact_preview_payload(artifact_id)
        )

    @app.delete('/api/artifacts/<artifact_id>')
    def delete_artifact(artifact_id):
        return responder.file_endpoint(
            lambda: web_service.delete_artifact(artifact_id)
        )

    @app.post('/api/artifacts/clear')
    def clear_artifacts():
        def _execute():
            payload = get_json_payload()
            artifact_type = (payload.get('type') or '').strip()
            hostname = (payload.get('hostname') or '').strip()

            if not artifact_type:
                raise ValueError('type is required')

            return web_service.clear_artifacts(artifact_type, hostname=hostname)

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/files/upload')
    def upload_file():
        def _execute():
            upload = get_required_upload()

            artifact_type = get_optional_form_text('artifact_type', 'files')
            category = get_optional_form_text('category', '')
            client_id = get_optional_form_text('client_id', '')
            hostname = get_optional_form_text('hostname', '')
            job_id = get_optional_form_text('job_id', '')
            job_name = get_optional_form_text('job_name', '')
            job_key = get_optional_form_text('job_key', '')
            source_type = get_optional_form_text('source_type', 'client_upload')
            related_path = get_optional_form_text('related_path', '')
            source_command_id = parse_optional_int_form('source_command_id')
            extra = parse_optional_json_form('extra')

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

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.errorhandler(413)
    def file_too_large(_):
        return responder.fail('File is too large', 413)

    @app.put('/api/artifacts/<artifact_id>/content')
    def update_artifact_content(artifact_id):
        """
        更新 Artifact 文件内容
        """

        def _execute():
            payload = get_json_payload()
            content = payload.get('content', '')
            encoding = (payload.get('encoding') or 'utf-8').strip()

            if content is None:
                raise ValueError('content is required')

            # 获取 artifact 信息
            artifact = web_service.get_artifact_by_id(artifact_id)
            if not artifact:
                raise FileNotFoundError('Artifact not found')

            file_path = artifact.get('saved_path', '')
            if not file_path or not os.path.isfile(file_path):
                raise FileNotFoundError('Artifact file not found')

            # 检查是否是文本文件（preview_type 为 text）
            preview_type = artifact_service.guess_preview_type(artifact.get('original_name', ''))
            if preview_type != 'text':
                raise ValueError('Only text files can be edited')

            # 写入新内容
            try:
                with open(file_path, 'w', encoding=encoding) as f:
                    f.write(content)
            except UnicodeEncodeError:
                # 如果指定编码失败，尝试 utf-8
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                encoding = 'utf-8'

            # 更新 artifact 元数据中的大小和修改时间
            file_size = os.path.getsize(file_path)

            # 更新 meta 文件
            meta_path = artifact.get('_meta_path', '')
            if meta_path and os.path.isfile(meta_path):
                import json
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)
                    meta['size'] = file_size
                    meta['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    with open(meta_path, 'w', encoding='utf-8') as f:
                        json.dump(meta, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass

            return {
                'artifact_id': artifact_id,
                'size': file_size,
                'encoding': encoding,
                'message': 'File updated successfully'
            }

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.post('/api/agent/build')
    def build_agent():
        """构建 Agent"""

        def _execute():
            payload = get_json_payload()
            server_host = (payload.get('server_host') or '').strip()
            server_port = payload.get('server_port')
            web_port = payload.get('web_port')
            target_os = (payload.get('target_os') or 'mac').strip()
            builder = (payload.get('builder') or 'pyinstaller').strip()
            target_arch = (payload.get('target_arch') or 'auto').strip()

            if not server_host:
                raise ValueError('server_host is required')
            if not server_port:
                raise ValueError('server_port is required')

            try:
                server_port = int(server_port)
            except ValueError:
                raise ValueError('server_port must be integer')

            result = web_service.build_agent(
                server_host, server_port, web_port, target_os, builder, target_arch
            )

            return result

        return responder.json_endpoint(_execute, default_error_status=500)

    @app.get('/api/agent/download/<filename>')
    def download_agent(filename):
        """下载构建好的 Agent"""
        try:
            file_path = os.path.join(web_service.agent_builder.output_dir, filename)
            if not os.path.isfile(file_path):
                return responder.fail('File not found', 404)

            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            return responder.map_common_error(e)

    @app.delete('/api/agent/cleanup')
    def cleanup_agent_build():
        """清理构建临时文件"""

        def _execute():
            work_dir = (request.json or {}).get('work_dir', '')
            if work_dir:
                web_service.cleanup_agent_build(work_dir)
            return {'cleaned': True}

        return responder.json_endpoint(_execute)

    return app
