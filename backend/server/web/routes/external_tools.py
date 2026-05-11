import os

from flask import Blueprint, request, send_file

from server.web.api_response import WebApiResponder
from server.web.auth_guard import allow_anonymous
from server.web.request_parsers import get_json_payload, get_optional_tab_id


def create_external_tool_blueprint(server_instance):
    blueprint = Blueprint('external_tools', __name__)
    external_tool_api = server_instance.web_service.external_tool_api
    request_context = external_tool_api.request_context
    catalog_api = external_tool_api.catalog
    package_api = external_tool_api.package_runtime
    server_instance_api = external_tool_api.server_instances
    client_lifecycle_api = external_tool_api.client_lifecycle
    responder = WebApiResponder()

    @blueprint.get('/api/external-tools/catalog')
    def list_external_tools():
        return responder.json_endpoint(
            lambda: catalog_api.list_catalog(),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/catalog')
    def list_client_external_tools(client_id):
        def _execute():
            platform_alias, arch = request_context.resolve_client_target(client_id, get_json_payload())
            return catalog_api.list_client_catalog(
                client_id,
                tab_id=get_optional_tab_id(),
                platform_alias=platform_alias,
                arch=arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>')
    def get_external_tool(tool_id):
        return responder.json_endpoint(
            lambda: catalog_api.get_tool(tool_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>/meta/content')
    def read_external_tool_meta(tool_id):
        return responder.json_endpoint(
            lambda: catalog_api.read_meta_content(tool_id),
            default_error_status=500,
        )

    @blueprint.post('/api/external-tools/<tool_id>/meta/content')
    def save_external_tool_meta(tool_id):
        def _execute():
            payload = get_json_payload()
            return catalog_api.save_meta_content(tool_id, str(payload.get('content') or ''))
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>/download')
    @allow_anonymous
    def download_external_tool_by_id(tool_id):
        try:
            platform_alias, arch = request_context.target_from_query(request.args)
            filename = catalog_api.get_package_download_filename(tool_id, platform_alias=platform_alias, arch=arch)
            file_path = catalog_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    @blueprint.get('/api/external-tools/packages/<filename>')
    @allow_anonymous
    def download_external_tool_package(filename):
        try:
            file_path = catalog_api.get_package_path(filename)
            return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))
        except Exception as e:
            return responder.map_common_error(e)

    # Server lifecycle.
    @blueprint.get('/api/external-tools/<tool_id>/server/instances')
    def list_server_instances(tool_id):
        return responder.json_endpoint(
            lambda: server_instance_api.list_server_instances(tool_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/server/instances')
    def list_all_server_instances():
        return responder.json_endpoint(
            lambda: server_instance_api.list_all_server_instances(),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/instances')
    def list_all_client_instances(client_id):
        return responder.json_endpoint(
            lambda: client_lifecycle_api.list_all_client_instances(
                client_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/start')
    def start_server_instance(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return server_instance_api.start_server_instance(
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/oneshot')
    def run_server_oneshot(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return server_instance_api.run_server_oneshot(tool_id, params=ctx.params)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/install')
    def install_server_tool(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return package_api.install_server_tool(
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/install-status')
    def server_install_status(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return package_api.server_install_status(
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/uninstall')
    def uninstall_server_tool(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return package_api.uninstall_server_tool(
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/clear-cache')
    def clear_server_package_cache(tool_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return package_api.clear_server_package_cache(
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/stop')
    def stop_server_instance(tool_id, instance_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return server_instance_api.stop_server_instance(tool_id, instance_id=instance_id, params=ctx.params)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.get('/api/external-tools/<tool_id>/server/instances/<instance_id>/status')
    def status_server_instance(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: server_instance_api.status_server_instance(tool_id, instance_id=instance_id),
            default_error_status=500,
        )

    @blueprint.get('/api/external-tools/<tool_id>/server/instances/<instance_id>/logs')
    def read_server_instance_logs(tool_id, instance_id):
        def _execute():
            max_bytes = request_context.max_bytes_from_query(request.args)
            return server_instance_api.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/remove')
    def remove_server_instance(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: server_instance_api.remove_server_instance(tool_id, instance_id=instance_id),
            default_error_status=500,
        )

    @blueprint.post('/api/external-tools/<tool_id>/server/instances/<instance_id>/clear-logs')
    def clear_server_instance_logs(tool_id, instance_id):
        return responder.json_endpoint(
            lambda: server_instance_api.clear_server_logs(tool_id, instance_id=instance_id),
            default_error_status=500,
        )

    # Client lifecycle. These endpoints submit commands to the target client.
    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances')
    def list_client_instances(client_id, tool_id):
        return responder.json_endpoint(
            lambda: client_lifecycle_api.list_client_instances(
                client_id,
                tool_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/start')
    def start_client_instance(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.start_client_instance(
                client_id,
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/oneshot')
    def run_client_oneshot(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.run_client_oneshot(
                client_id,
                tool_id,
                params=ctx.params,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/install')
    def install_client_tool(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.install_client_tool(
                client_id,
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/install-status')
    def client_install_status(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.client_install_status(
                client_id,
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/uninstall')
    def uninstall_client_tool(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.uninstall_client_tool(
                client_id,
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/clear-cache')
    def clear_client_package_cache(client_id, tool_id):
        def _execute():
            ctx = request_context.client_payload(client_id, get_json_payload(), tab_id=get_optional_tab_id())
            return client_lifecycle_api.clear_client_package_cache(
                client_id,
                tool_id,
                params=ctx.params,
                instance_id=ctx.instance_id,
                tab_id=ctx.tab_id,
                platform_alias=ctx.platform_alias,
                arch=ctx.arch,
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/stop')
    def stop_client_instance(client_id, tool_id, instance_id):
        def _execute():
            ctx = request_context.server_payload(get_json_payload())
            return client_lifecycle_api.stop_client_instance(
                client_id,
                tool_id,
                instance_id=instance_id,
                params=ctx.params,
                tab_id=get_optional_tab_id(),
            )
        return responder.json_endpoint(_execute, default_error_status=500)

    @blueprint.post('/api/connections/<client_id>/external-tools/<tool_id>/instances/<instance_id>/status')
    def status_client_instance(client_id, tool_id, instance_id):
        return responder.json_endpoint(
            lambda: client_lifecycle_api.status_client_instance(
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
            max_bytes = request_context.max_bytes_from_payload(payload)
            return client_lifecycle_api.read_client_logs(
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
            lambda: client_lifecycle_api.remove_client_instance(
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
            lambda: client_lifecycle_api.clear_client_logs(
                client_id,
                tool_id,
                instance_id=instance_id,
                tab_id=get_optional_tab_id(),
            ),
            default_error_status=500,
        )

    return blueprint
