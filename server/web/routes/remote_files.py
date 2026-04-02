from flask import Blueprint

from server.web.api_response import WebApiResponder
from server.web.request_parsers import get_json_payload, get_optional_remote_path, parse_paging_args


def create_remote_files_blueprint(server_instance):
    blueprint = Blueprint('remote_files', __name__)
    web_service = server_instance.web_service
    responder = WebApiResponder()

    @blueprint.get('/api/connections/<client_id>/remote-files')
    def browse_remote_files(client_id):
        def _execute():
            paging = parse_paging_args(default_page=1, default_page_size=100)
            return web_service.browse_remote_directory(
                client_id,
                get_optional_remote_path(),
                page=paging['page'],
                page_size=paging['page_size'],
                show_hidden=paging['show_hidden'],
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/mkdir')
    def create_remote_directory(client_id):
        def _execute():
            payload = get_json_payload()
            path = (payload.get('path') or '').strip()
            if not path:
                raise ValueError('path is required')
            return web_service.create_remote_directory(client_id, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/rename')
    def rename_remote_path(client_id):
        def _execute():
            payload = get_json_payload()
            old_path = (payload.get('old_path') or '').strip()
            new_name = (payload.get('new_name') or '').strip()

            if not old_path:
                raise ValueError('old_path is required')
            if not new_name:
                raise ValueError('new_name is required')

            return web_service.rename_remote_path(client_id, old_path, new_name)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>/remote-files')
    def delete_remote_file_or_directory(client_id):
        def _execute():
            path = get_optional_remote_path()
            if not path:
                raise ValueError('path is required')
            return web_service.delete_remote_path(client_id, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/download')
    def download_remote_file(client_id):
        def _execute():
            path = get_optional_remote_path()
            if not path:
                raise ValueError('path is required')
            return web_service.download_remote_file(client_id, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/download-zip')
    def download_remote_paths_as_zip(client_id):
        def _execute():
            payload = get_json_payload()
            paths = payload.get('paths') or []
            archive_name = (payload.get('archive_name') or '').strip()

            if not isinstance(paths, list) or not paths:
                raise ValueError('paths is required')

            return web_service.download_remote_paths_as_zip(client_id, paths, archive_name)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.delete('/api/connections/<client_id>/remote-files/batch')
    def delete_remote_files_batch(client_id):
        def _execute():
            payload = get_json_payload()
            paths = payload.get('paths') or []
            if not isinstance(paths, list) or not paths:
                raise ValueError('paths is required and must be a non-empty list')
            return web_service.delete_remote_paths(client_id, paths)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/preview')
    def preview_remote_file(client_id):
        def _execute():
            payload = get_json_payload()
            path = (payload.get('path') or '').strip()
            if not path:
                raise ValueError('path is required')
            return web_service.preview_remote_file(client_id, path)

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/remote-files/save')
    def save_remote_file(client_id):
        def _execute():
            payload = get_json_payload()
            path = (payload.get('path') or '').strip()
            content = payload.get('content', '')
            encoding = (payload.get('encoding') or 'utf-8').strip()

            if not path:
                raise ValueError('path is required')

            return web_service.remote_file_service.save_file_content(
                client_id, path, content, encoding
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    return blueprint
