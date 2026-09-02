import os

from flask import Flask, request, send_file

from server.config.config import WEB_HTTP_UPLOAD_MAX_BYTES
from server.web.api_response import WebApiResponder
from server.web.request_parsers import (
    get_optional_form_text,
    get_required_upload,
    parse_optional_int_form,
    parse_optional_json_form,
)


def create_file_transfer_app(server_instance):
    """
    Client <-> Server 专用文件传输 WSGI 应用。

    该应用由 Werkzeug 直接监听独立端口，不挂载到 FastAPI/ASGI，避免大文件
    request body 经过 WSGIMiddleware 聚合。浏览器侧文件 API 仍由主 Web 应用处理。
    """
    app = Flask('rch_file_transfer')
    app.config['MAX_CONTENT_LENGTH'] = WEB_HTTP_UPLOAD_MAX_BYTES

    artifact_api = server_instance.web_service.artifact_api
    responder = WebApiResponder()

    @app.post('/api/files/upload')
    def upload_file():
        def _execute():
            upload = get_required_upload()
            artifact_type = get_optional_form_text('artifact_type', 'files')
            category = get_optional_form_text('category', '')
            client_id = get_optional_form_text('client_id', '')
            hostname = get_optional_form_text('hostname', '')
            machine_id = get_optional_form_text('machine_id', '')
            job_id = get_optional_form_text('job_id', '')
            job_name = get_optional_form_text('job_name', '')
            job_key = get_optional_form_text('job_key', '')
            source_command_id = parse_optional_int_form('source_command_id')
            transfer_buffer_size = parse_optional_int_form('transfer_buffer_size')
            extra = parse_optional_json_form('extra')
            return artifact_api.save_http_uploaded_file(
                upload,
                artifact_type=artifact_type,
                category=category,
                client_id=client_id,
                hostname=hostname,
                machine_id=machine_id,
                job_id=job_id,
                job_name=job_name,
                job_key=job_key,
                source_command_id=source_command_id,
                transfer_buffer_size=transfer_buffer_size,
                extra=extra,
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
        except Exception as exc:
            return responder.map_common_error(exc)

    @app.errorhandler(413)
    def file_too_large(_):
        return responder.fail('File is too large', 413)

    return app
