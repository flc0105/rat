from flask import Blueprint, request, Response

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload


def create_background_job_blueprint(server_instance):
    blueprint = Blueprint('background_jobs', __name__)
    web_service = server_instance.web_service
    background_job_service = web_service.background_job_service
    responder = WebApiResponder()

    @blueprint.get('/api/server/jobs/list')
    def list_server_jobs():
        """列出所有可用的远程脚本"""
        return responder.json_endpoint(
            lambda: web_service.list_server_jobs(),
            default_error_status=500
        )

    @blueprint.get('/api/server/jobs/download')
    def download_server_job():
        """下载脚本内容（供 Client 使用）"""
        script_name = request.args.get('name', '').strip()
        if not script_name:
            return responder.fail('script name is required', 400)

        try:
            content = web_service.get_server_job_content(script_name)
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
            return web_service.save_server_job_content(name, content)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/server/jobs/upload')
    def upload_server_job():
        def _execute():
            file_obj = request.files.get('file')
            if file_obj is None:
                raise ValueError('file is required')
            return web_service.upload_server_job(file_obj)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/server/jobs/delete')
    def delete_server_job():
        def _execute():
            payload = get_json_payload()
            name = (payload.get('name') or '').strip()
            if not name:
                raise ValueError('job name is required')

            return web_service.delete_server_job(name)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/background-jobs/modules')
    def list_available_background_jobs(client_id):
        return responder.json_endpoint(
            lambda: background_job_service.list_available_jobs(client_id),
            default_error_status=500
        )

    @blueprint.get('/api/connections/<client_id>/background-jobs/catalog')
    def list_background_job_catalog(client_id):
        def _execute():
            client_items = background_job_service.list_available_jobs(client_id) or []
            server_items = web_service.list_server_jobs() or []

            normalized = []
            seen = set()

            for item in client_items:
                if not isinstance(item, dict):
                    continue
                job_name = str(item.get('job_name') or item.get('name') or item.get('job_key') or '').strip()
                if not job_name:
                    continue
                source = str(item.get('source') or 'client').strip() or 'client'
                dedupe_key = (source, job_name)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                normalized.append({
                    **item,
                    'job_name': job_name,
                    'job_key': str(item.get('job_key') or job_name).strip() or job_name,
                    'display_name': str(item.get('display_name') or job_name).strip() or job_name,
                    'source': source,
                })

            for item in server_items:
                if not isinstance(item, dict):
                    continue
                job_name = str(item.get('job_name') or item.get('name') or item.get('job_key') or '').strip()
                if not job_name:
                    continue
                dedupe_key = ('server', job_name)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                normalized.append({
                    **item,
                    'job_name': job_name,
                    'job_key': str(item.get('job_key') or job_name).strip() or job_name,
                    'display_name': str(item.get('display_name') or item.get('name') or job_name).strip() or job_name,
                    'source': 'server',
                })

            normalized.sort(key=lambda item: (item.get('source') != 'client', item.get('job_name', '').lower()))
            return normalized

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/connections/<client_id>/background-jobs')
    def list_background_jobs(client_id):
        return responder.json_endpoint(
            lambda: background_job_service.list_jobs(client_id),
            default_error_status=500
        )

    @blueprint.post('/api/connections/<client_id>/background-jobs/start')
    def start_background_job(client_id):
        def _execute():
            payload = get_json_payload()
            job_name = (payload.get('job_name') or '').strip()
            if not job_name:
                raise ValueError('job_name is required')

            source = (payload.get('source') or 'auto').strip().lower()
            if source not in ('auto', 'client', 'server'):
                source = 'auto'

            command = f'start_job {job_name}'
            # if source == 'server':
            #     command = f'start_job_remote {job_name}'

            result = web_service.submit_web_command(client_id, command)
            if isinstance(result, dict):
                result['job_name'] = job_name
                result['source'] = source
            return result

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/background-jobs/stop')
    def stop_background_job(client_id):
        def _execute():
            payload = get_json_payload()
            job_key = (payload.get('job_key') or '').strip()
            if not job_key:
                raise ValueError('job_key is required')
            return background_job_service.stop_job(client_id, job_key)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/background-jobs/report')
    def report_background_job_event():
        def _execute():
            payload = get_json_payload()
            return background_job_service.ingest_report(payload)

        return responder.json_endpoint(_execute, default_error_status=500)



    return blueprint