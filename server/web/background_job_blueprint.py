import os

from flask import Blueprint, jsonify, request, send_from_directory


def create_background_job_blueprint(server_instance):
    blueprint = Blueprint('background_jobs', __name__)
    web_service = server_instance.web_service
    file_service = web_service.file_service
    background_job_service = web_service.background_job_service

    def _ok(data=None, message='ok', code=0, http_status=200):
        payload = {
            'code': code,
            'message': message,
        }
        if data is not None:
            payload['data'] = data
        return jsonify(payload), http_status

    def _fail(message, http_status=400, code=1):
        return jsonify({
            'code': code,
            'message': str(message),
        }), http_status

    def _json_payload():
        return request.get_json(silent=True) or {}

    def _json_endpoint(func, default_error_status=400):
        try:
            result = func()
            return _ok(result)
        except ValueError as e:
            return _fail(e, 400)
        except FileNotFoundError as e:
            return _fail(e, 404)
        except Exception as e:
            return _fail(e, default_error_status)

    @blueprint.get('/api/connections/<client_id>/background-jobs/modules')
    def list_available_background_jobs(client_id):
        return _json_endpoint(
            lambda: background_job_service.list_available_jobs(client_id),
            default_error_status=500
        )

    @blueprint.get('/api/connections/<client_id>/background-jobs')
    def list_background_jobs(client_id):
        return _json_endpoint(
            lambda: background_job_service.list_jobs(client_id),
            default_error_status=500
        )

    @blueprint.post('/api/connections/<client_id>/background-jobs/start')
    def start_background_job(client_id):
        def _execute():
            payload = _json_payload()
            job_name = (payload.get('job_name') or '').strip()
            if not job_name:
                raise ValueError('job_name is required')
            return background_job_service.start_job(client_id, job_name)

        return _json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/background-jobs/stop')
    def stop_background_job(client_id):
        def _execute():
            payload = _json_payload()
            job_key = (payload.get('job_key') or '').strip()
            if not job_key:
                raise ValueError('job_key is required')
            return background_job_service.stop_job(client_id, job_key)

        return _json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/background-jobs/report')
    def report_background_job_event():
        def _execute():
            payload = _json_payload()
            return background_job_service.ingest_report(payload)

        return _json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/background-job-files/<path:relative_path>')
    def download_background_job_file(relative_path):
        def _execute():
            file_path = file_service.get_safe_http_upload_file_path(relative_path)
            if not os.path.isfile(file_path):
                raise FileNotFoundError('file not found')

            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, as_attachment=True, download_name=filename)

        try:
            return _execute()
        except FileNotFoundError as e:
            return _fail(e, 404)
        except Exception as e:
            return _fail(e, 500)

    @blueprint.get('/api/background-job-files/<path:relative_path>/raw')
    def get_background_job_file_raw(relative_path):
        def _execute():
            file_path = file_service.get_safe_http_upload_file_path(relative_path)
            if not os.path.isfile(file_path):
                raise FileNotFoundError('file not found')

            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, as_attachment=False)

        try:
            return _execute()
        except FileNotFoundError as e:
            return _fail(e, 404)
        except Exception as e:
            return _fail(e, 500)

    @blueprint.get('/api/background-job-files/<path:relative_path>/preview')
    def preview_background_job_file(relative_path):
        return _json_endpoint(
            lambda: file_service.build_http_upload_preview_payload(relative_path),
            default_error_status=500
        )

    return blueprint