import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import get_json_payload, get_optional_tab_id


def create_external_tool_blueprint(server_instance):
    blueprint = Blueprint('external_tools', __name__)
    web_service = server_instance.web_service
    external_tool_api = web_service.external_tool_api
    responder = WebApiResponder()

    def _params_from_payload():
        payload = get_json_payload()
        params = payload.get('params') or {}
        if not isinstance(params, dict):
            raise ValueError('params must be an object')
        return payload, params

    def _target_from_payload(payload):
        platform_alias = str(payload.get('platform') or payload.get('platform_alias') or '').strip()
        arch = str(payload.get('arch') or payload.get('architecture') or '').strip()
        return platform_alias, arch

    @blueprint.get('/api/external-tools/catalog')
    def list_external_tools():
        return responder.json_endpoint(
            lambda: external_tool_api.list_catalog(),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/catalog')
    def list_client_external_tools(client_id):
        def _execute():
            payload = get_json_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.list_client_catalog(
                client_id,
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>')
    def get_external_tool(tool_id):
        return responder.json_endpoint(
            lambda: external_tool_api.get_tool(tool_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>/meta/content')
    def read_external_tool_meta(tool_id):
        return responder.json_endpoint(
            lambda: external_tool_api.read_meta_content(tool_id),
            default_error_status=500,
        )

    @blueprint.post('/api/external-tools/<tool_id>/meta/content')
    def save_external_tool_meta(tool_id):
        def _execute():
            payload = get_json_payload()
            return external_tool_api.save_meta_content(tool_id, str(payload.get('content') or ''))
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>/download')
    @allow_anonymous
    def download_external_tool_by_id(tool_id):
        try:
            platform_alias = str(request.args.get('platform') or request.args.get('platform_alias') or '').strip()
            arch = str(request.args.get('arch') or request.args.get('architecture') or '').strip()
            filename = external_tool_api.get_package_download_filename(tool_id, platform_alias=platform_alias, arch=arch)
            file_path = external_tool_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/external-tools/packages/<filename>')
    @allow_anonymous
    def download_external_tool_package(filename):
        try:
            file_path = external_tool_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    # Server lifecycle.
    @blueprint.get('/api/external-tools/<tool_id>/server/instances')
    def list_server_instances(tool_id):
        return responder.json_endpoint(
            lambda: external_tool_api.list_server_instances(tool_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/server/instances')
    def list_all_server_instances():
        return responder.json_endpoint(
            lambda: external_tool_api.list_all_server_instances(),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/instances')
    def list_all_client_instances(client_id):
        return responder.json_endpoint(
            lambda: external_tool_api.list_all_client_instances(
                client_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )


    @blueprint.post('/api/external-tools/<tool_id>/server/instances/start')
    def start_server_instance(tool_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.start_server_instance(
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                install_if_needed=False,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/install')
    def install_server_tool(tool_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.install_server_tool(
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/install-status')
    def server_install_status(tool_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.server_install_status(
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/uninstall')
    def uninstall_server_tool(tool_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.uninstall_server_tool(
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/clear-cache')
    def clear_server_package_cache(tool_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.clear_server_package_cache(
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/stop')
    def stop_server_instance(tool_id, instance_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.stop_server_instance(tool_id, instance_id=instance_id, params=params)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>/server/instances/<instance_id>/status')
    def status_server_instance(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.status_server_instance(tool_id, instance_id=instance_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>/server/instances/<instance_id>/logs')
    def read_server_instance_logs(tool_id, instance_id):
        def _execute():
            max_bytes = request.args.get('bytes') or request.args.get('max_bytes') or None
            return external_tool_api.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/remove')
    def remove_server_instance(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.remove_server_instance(tool_id, instance_id=instance_id),
            default_error_status=500,
        )

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/clear-logs')
    def clear_server_instance_logs(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.clear_server_logs(tool_id, instance_id=instance_id),
            default_error_status=500,
        )


    # Client lifecycle. These endpoints submit commands to the target client.
    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances')
    def list_client_instances(client_id, tool_id):
        return responder.json_endpoint(
            lambda: external_tool_api.list_client_instances(
                client_id,
                tool_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/start')
    def start_client_instance(client_id, tool_id):
        def _execute():
            payload, params = _params_from_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.start_client_instance(
                client_id,
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                install_if_needed=False,
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/install')
    def install_client_tool(client_id, tool_id):
        def _execute():
            payload, params = _params_from_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.install_client_tool(
                client_id,
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/install-status')
    def client_install_status(client_id, tool_id):
        def _execute():
            payload, params = _params_from_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.client_install_status(
                client_id,
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/uninstall')
    def uninstall_client_tool(client_id, tool_id):
        def _execute():
            payload, params = _params_from_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.uninstall_client_tool(
                client_id,
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/clear-cache')
    def clear_client_package_cache(client_id, tool_id):
        def _execute():
            payload, params = _params_from_payload()
            platform_alias, arch = _target_from_payload(payload)
            return external_tool_api.clear_client_package_cache(
                client_id,
                tool_id,
                params=params,
                instance_id=str(payload.get('instance_id') or '').strip(),
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )

        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/stop')
    def stop_client_instance(client_id, tool_id, instance_id):
        def _execute():
            payload, params = _params_from_payload()
            return external_tool_api.stop_client_instance(
                client_id,
                tool_id,
                instance_id=instance_id,
                params=params,
                tab_id=get_optional_tab_id(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/status')
    def status_client_instance(client_id, tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.status_client_instance(
                client_id,
                tool_id,
                instance_id=instance_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/logs')
    def read_client_instance_logs(client_id, tool_id, instance_id):
        def _execute():
            payload = get_json_payload()
            max_bytes = payload.get('bytes') or payload.get('max_bytes') or None
            return external_tool_api.read_client_logs(
                client_id,
                tool_id,
                instance_id=instance_id,
                max_bytes=max_bytes,
                tab_id=get_optional_tab_id(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/remove')
    def remove_client_instance(client_id, tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.remove_client_instance(
                client_id,
                tool_id,
                instance_id=instance_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/clear-logs')
    def clear_client_instance_logs(client_id, tool_id, instance_id):
        return responder.json_endpoint(
            lambda: external_tool_api.clear_client_logs(
                client_id,
                tool_id,
                instance_id=instance_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )


    return blueprint