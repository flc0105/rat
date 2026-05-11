class WebExternalToolCatalogApi:
    def __init__(self, catalog_service, runtime_service):
        self.catalog_service = catalog_service
        self.runtime_service = runtime_service

    def list_catalog(self):
        catalog = self.catalog_service.get_catalog()
        server_platform = catalog.get('server_platform') or ''
        server_arch = catalog.get('server_arch') or ''
        if not server_platform or not server_arch:
            raise ValueError(f'server platform and arch are required, got {server_platform or "unknown"}/{server_arch or "unknown"}')
        for item in catalog.get('items') or []:
            if item.get('error') or not self._package_supports_target(item, server_platform, server_arch):
                continue
            try:
                item['install_status'] = self.runtime_service.package_runtime.server_install_status(item.get('id') or '', params={}, instance_id='')
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
        status_result = self.runtime_service.client_lifecycle_runtime.client_install_statuses(
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
        # Package-only API. Do not fall back to legacy module lookup; callers must
        # use package ids here so id mistakes fail immediately.
        return self.catalog_service.get_package(tool_id)

    def get_package_path(self, filename: str):
        return self.catalog_service.get_package_path(filename)

    def get_package_download_filename(self, package_id: str, platform_alias: str = '', arch: str = ''):
        return self.catalog_service.get_package_download_filename(package_id, platform_alias=platform_alias, arch=arch)

    def read_meta_content(self, package_id: str):
        return self.catalog_service.read_meta_content(package_id)

    def save_meta_content(self, package_id: str, content: str):
        return self.catalog_service.save_meta_content(package_id, content)

    def _package_supports_target(self, item: dict, platform_alias: str = '', arch: str = '') -> bool:
        if item.get('error'):
            return False
        try:
            self.catalog_service.select_package_key(item, platform_alias=platform_alias, arch=arch)
            return True
        except Exception:
            return False
