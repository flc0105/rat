from core.platform.platform_identity import detect_platform_alias


class WebExternalToolApi:
    def __init__(self, catalog_service, runtime_service):
        self.catalog_service = catalog_service
        self.runtime_service = runtime_service

    def _normalize_platform(self, value: str = '') -> str:
        return self.catalog_service._normalize_platform(value or '')

    def _normalize_arch(self, value: str = '') -> str:
        return self.catalog_service._normalize_arch(value or '')

    def _package_supports_target(self, item: dict, platform_alias: str = '', arch: str = '') -> bool:
        if item.get('error'):
            return False
        try:
            self.catalog_service.select_package_key(item, platform_alias=platform_alias, arch=arch)
            return True
        except Exception:
            return False

    def list_catalog(self):
        catalog = self.catalog_service.get_catalog()
        server_platform = catalog.get('server_platform') or detect_platform_alias()
        server_arch = catalog.get('server_arch') or self.catalog_service._normalize_arch('')
        for item in catalog.get('items') or []:
            if item.get('error') or not self._package_supports_target(item, server_platform, server_arch):
                continue
            try:
                item['install_status'] = self.runtime_service.server_install_status(item.get('id') or '', params={}, instance_id='')
            except Exception as e:
                item['install_status'] = {
                    'tool_id': item.get('id') or '',
                    'package_id': item.get('id') or '',
                    'side': 'server',
                    'installed': None,
                    'error': str(e),
                    'message': str(e),
                }
        return catalog

    def list_client_catalog(self, client_id: str, tab_id: str = '', platform_alias: str = '', arch: str = ''):
        # Do not call list_catalog() here: that injects server install_status into
        # package items. Client catalog status must be exclusively client FS state,
        # otherwise a stale/failed client status read can leave the UI showing the
        # server's Installed value for the selected client.
        catalog = self.catalog_service.get_catalog()
        client_items = [item for item in (catalog.get('items') or []) if not item.get('error') and self._package_supports_target(item, platform_alias, arch)]
        for item in client_items:
            item.pop('install_status', None)
        if not client_items:
            catalog['items'] = client_items
            catalog['client_install_statuses'] = []
            return catalog
        status_result = self.runtime_service.client_install_statuses(
            client_id,
            client_items,
            tab_id=tab_id,
            platform_alias=platform_alias,
            arch=arch,
        )
        statuses = status_result.get('items') if isinstance(status_result, dict) else []
        by_package_id = {str(item.get('package_id') or item.get('tool_id') or ''): item for item in (statuses or []) if isinstance(item, dict)}
        for item in client_items:
            status = by_package_id.get(str(item.get('id') or ''))
            item['install_status'] = status if status else {
                'tool_id': item.get('id') or '',
                'package_id': item.get('id') or '',
                'side': 'client',
                'installed': False,
                'error': 'client status not returned',
                'message': 'client status not returned',
            }
        catalog['items'] = client_items
        catalog['client_install_statuses'] = statuses or []
        return catalog

    def get_tool(self, tool_id: str):
        # Package-first UI uses this for package details/meta-adjacent inspection.
        try:
            return self.catalog_service.get_package(tool_id)
        except Exception:
            return self.catalog_service.get_tool(tool_id)

    def get_package_path(self, filename: str):
        return self.catalog_service.get_package_path(filename)

    def get_package_download_filename(self, package_id: str, platform_alias: str = '', arch: str = ''):
        return self.catalog_service.get_package_download_filename(package_id, platform_alias=platform_alias, arch=arch)

    def read_meta_content(self, package_id: str):
        return self.catalog_service.read_meta_content(package_id)

    def save_meta_content(self, package_id: str, content: str):
        return self.catalog_service.save_meta_content(package_id, content)

    # Server-side package lifecycle.
    def install_server_tool(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.install_server_tool(package_id, params=params, instance_id=instance_id)

    def server_install_status(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.server_install_status(package_id, params=params, instance_id=instance_id)

    def uninstall_server_tool(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.uninstall_server_tool(package_id, params=params, instance_id=instance_id)

    def clear_server_package_cache(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.clear_server_package_cache(package_id, params=params, instance_id=instance_id)

    # Server-side module lifecycle.
    def start_server_instance(self, tool_id: str, params=None, instance_id: str = '', install_if_needed: bool = False):
        del install_if_needed
        return self.runtime_service.start_server_instance(tool_id, params=params, instance_id=instance_id, install_if_needed=False)

    def stop_server_instance(self, tool_id: str, instance_id: str, params=None):
        return self.runtime_service.stop_server_instance(tool_id, instance_id=instance_id, params=params)

    def status_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.status_server_instance(tool_id, instance_id=instance_id)

    def list_server_instances(self, tool_id: str):
        return self.runtime_service.list_server_instances(tool_id)

    def list_all_server_instances(self):
        modules = [item for item in (self.catalog_service.get_catalog().get('modules') or []) if not item.get('error')]
        return self.runtime_service.list_all_server_instances(modules)

    def list_all_client_instances(self, client_id: str, tab_id: str = ''):
        modules = [item for item in (self.catalog_service.get_catalog().get('modules') or []) if not item.get('error')]
        return self.runtime_service.list_all_client_instances(client_id, modules, tab_id=tab_id)

    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes=None):
        return self.runtime_service.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)

    def remove_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.remove_server_instance(tool_id, instance_id=instance_id)

    def clear_server_logs(self, tool_id: str, instance_id: str):
        return self.runtime_service.clear_server_logs(tool_id, instance_id=instance_id)

    # Client-side package lifecycle.
    def install_client_tool(self, client_id: str, package_id: str, params=None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = ''):
        return self.runtime_service.install_client_tool(client_id, package_id, params=params, tab_id=tab_id, instance_id=instance_id, platform_alias=platform_alias, arch=arch)

    def client_install_status(self, client_id: str, package_id: str, params=None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = ''):
        return self.runtime_service.client_install_status(client_id, package_id, params=params, tab_id=tab_id, instance_id=instance_id, platform_alias=platform_alias, arch=arch)

    def client_install_statuses(self, client_id: str, tab_id: str = '', platform_alias: str = '', arch: str = ''):
        packages = [item for item in (self.catalog_service.get_catalog().get('items') or []) if not item.get('error')]
        return self.runtime_service.client_install_statuses(client_id, packages, tab_id=tab_id, platform_alias=platform_alias, arch=arch)

    def uninstall_client_tool(self, client_id: str, package_id: str, params=None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = ''):
        return self.runtime_service.uninstall_client_tool(client_id, package_id, params=params, tab_id=tab_id, instance_id=instance_id, platform_alias=platform_alias, arch=arch)

    def clear_client_package_cache(self, client_id: str, package_id: str, params=None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = ''):
        return self.runtime_service.clear_client_package_cache(client_id, package_id, params=params, tab_id=tab_id, instance_id=instance_id, platform_alias=platform_alias, arch=arch)

    # Client-side module lifecycle.
    def start_client_instance(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = '', install_if_needed: bool = False, platform_alias: str = '', arch: str = ''):
        del install_if_needed
        return self.runtime_service.start_client_instance(client_id, tool_id, params=params, tab_id=tab_id, instance_id=instance_id, install_if_needed=False, platform_alias=platform_alias, arch=arch)

    def stop_client_instance(self, client_id: str, tool_id: str, instance_id: str, params=None, tab_id: str = ''):
        return self.runtime_service.stop_client_instance(client_id, tool_id, instance_id=instance_id, params=params, tab_id=tab_id)

    def status_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = ''):
        return self.runtime_service.status_client_instance(client_id, tool_id, instance_id=instance_id, tab_id=tab_id)

    def list_client_instances(self, client_id: str, tool_id: str, tab_id: str = ''):
        return self.runtime_service.list_client_instances(client_id, tool_id, tab_id=tab_id)

    def read_client_logs(self, client_id: str, tool_id: str, instance_id: str, max_bytes=None, tab_id: str = ''):
        return self.runtime_service.read_client_logs(client_id, tool_id, instance_id=instance_id, max_bytes=max_bytes, tab_id=tab_id)

    def remove_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = ''):
        return self.runtime_service.remove_client_instance(client_id, tool_id, instance_id=instance_id, tab_id=tab_id)

    def clear_client_logs(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = ''):
        return self.runtime_service.clear_client_logs(client_id, tool_id, instance_id=instance_id, tab_id=tab_id)
