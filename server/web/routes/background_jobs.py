from flask import Blueprint, request, Response

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_background_job_blueprint(server_instance):
    blueprint = Blueprint('background_jobs', __name__)
    web_service = server_instance.web_service
    job_api = web_service.job_api
    responder = WebApiResponder()

    @blueprint.get('/api/server/jobs/list')
    def list_server_jobs():
        """列出所有可用的远程脚本"""
        return responder.json_endpoint(
            lambda: job_api.list_server_jobs(),
            default_error_status=500,
        )

    @blueprint.get('/api/server/jobs/download')
    def download_server_job():
        """下载脚本内容（供 Client 使用）"""
        script_name = request.args.get('name', '').strip()
        if not script_name:
            return responder.fail('script name is required', 400)

        try:
            content = job_api.get_server_job_content(script_name)
            return Response(content, mimetype='text/plain')
        except FileNotFoundError as e:
            return responder.fail(str(e), 404)
        except Exception as e:
            return responder.fail(str(e), 500)

    @blueprint.post('/api/server/jobs/save')
    def save_server_job():
        def _execute():
            payload = get_json_payload()
            name = (payload.get('name') or '').strip()
            content = payload.get('content', '')

            if not name:
                raise ValueError('job name is required')
            if content is None:
                raise ValueError('job content is required')

            return job_api.save_server_job_content(name, content)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/server/jobs/upload')
    def upload_server_job():
        def _execute():
            file_obj = request.files.get('file')
            if file_obj is None:
                raise ValueError('file is required')
            return job_api.upload_server_job(file_obj)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/server/jobs/delete')
    def delete_server_job():
        def _execute():
            payload = get_json_payload()
            name = (payload.get('name') or '').strip()
            if not name:
                raise ValueError('job name is required')

            return job_api.delete_server_job(name)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/background-jobs/modules')
    def list_available_background_jobs(client_id):
        return responder.json_endpoint(
            lambda: job_api.list_available_background_jobs(client_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/background-jobs/catalog')
    def list_background_job_catalog(client_id):
        return responder.json_endpoint(
            lambda: job_api.list_background_job_catalog(client_id),
            default_error_status=500,
        )

    @blueprint.get('/api/connections/<client_id>/background-jobs')
    def list_background_jobs(client_id):
        return responder.json_endpoint(
            lambda: job_api.list_background_jobs(client_id),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/background-jobs/start')
    def start_background_job(client_id):
        def _execute():
            payload = get_json_payload()
            job_name = (payload.get('job_name') or '').strip()
            if not job_name:
                raise ValueError('job_name is required')

            source = (payload.get('source') or 'auto').strip().lower()
            return job_api.start_background_job(client_id, job_name, source=source)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/background-jobs/stop')
    def stop_background_job(client_id):
        def _execute():
            payload = get_json_payload()
            job_key = (payload.get('job_key') or '').strip()
            if not job_key:
                raise ValueError('job_key is required')
            return job_api.stop_background_job(client_id, job_key)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/background-jobs/report')
    def report_background_job_event():
        def _execute():
            payload = get_json_payload()
            return job_api.ingest_background_job_report(payload)

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint