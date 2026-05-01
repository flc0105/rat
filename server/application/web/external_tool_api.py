class WebExternalToolApi:
    def __init__(self, catalog_service, runtime_service):
        self.catalog_service = catalog_service
        self.runtime_service = runtime_service

    def list_catalog(self):
        catalog = self.catalog_service.get_catalog()
        for item in catalog.get('items') or []:
            if item.get('error') or item.get('side') != 'server':
                continue
            try:
                item['install_status'] = self.runtime_service.server_install_status(item.get('id') or '', params={}, instance_id='')
            except Exception as e:
                item['install_status'] = {
                    'tool_id': item.get('id') or '',
                    'side': 'server',
                    'installed': None,
                    'error': str(e),
                    'message': str(e),
                }
        return catalog

    def list_client_catalog(self, client_id: str, tab_id: str = ''):
        catalog = self.list_catalog()
        client_items = [item for item in (catalog.get('items') or []) if item.get('side') == 'client' and not item.get('error')]
        if not client_items:
            catalog['client_install_statuses'] = []
            return catalog
        status_result = self.runtime_service.client_install_statuses(client_id, client_items, tab_id=tab_id)
        statuses = status_result.get('items') if isinstance(status_result, dict) else []
        by_tool_id = {str(item.get('tool_id') or ''): item for item in (statuses or []) if isinstance(item, dict)}
        for item in client_items:
            status = by_tool_id.get(str(item.get('id') or ''))
            if status:
                item['install_status'] = status
        catalog['client_install_statuses'] = statuses or []
        return catalog

    def get_tool(self, tool_id: str):
        return self.catalog_service.get_tool(tool_id)

    def get_package_path(self, filename: str):
        return self.catalog_service.get_package_path(filename)

    def read_meta_content(self, tool_id: str):
        return self.catalog_service.read_meta_content(tool_id)

    def save_meta_content(self, tool_id: str, content: str):
        return self.catalog_service.save_meta_content(tool_id, content)

    # Server-side lifecycle
    def start_server_instance(self, tool_id: str, params=None, instance_id: str = '', install_if_needed: bool = True):
        return self.runtime_service.start_server_instance(tool_id, params=params, instance_id=instance_id, install_if_needed=install_if_needed)

    def install_server_tool(self, tool_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.install_server_tool(tool_id, params=params, instance_id=instance_id)

    def server_install_status(self, tool_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.server_install_status(tool_id, params=params, instance_id=instance_id)

    def stop_server_instance(self, tool_id: str, instance_id: str, params=None):
        return self.runtime_service.stop_server_instance(tool_id, instance_id=instance_id, params=params)

    def status_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.status_server_instance(tool_id, instance_id=instance_id)

    def list_server_instances(self, tool_id: str):
        return self.runtime_service.list_server_instances(tool_id)

    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes=None):
        return self.runtime_service.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)

    def remove_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.remove_server_instance(tool_id, instance_id=instance_id)

    def clear_server_logs(self, tool_id: str, instance_id: str):
        return self.runtime_service.clear_server_logs(tool_id, instance_id=instance_id)

    # Backward-compatible old method name.
    def install_and_run_server(self, tool_id: str, params=None):
        return self.runtime_service.install_and_run_server(tool_id, params=params)

    # Client-side lifecycle submits commands to target client.
    def start_client_instance(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = '', install_if_needed: bool = True):
        return self.runtime_service.start_client_instance(client_id, tool_id, params=params, tab_id=tab_id, instance_id=instance_id, install_if_needed=install_if_needed)

    def install_client_tool(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = ''):
        return self.runtime_service.install_client_tool(client_id, tool_id, params=params, tab_id=tab_id, instance_id=instance_id)

    def client_install_status(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = ''):
        return self.runtime_service.client_install_status(client_id, tool_id, params=params, tab_id=tab_id, instance_id=instance_id)

    def client_install_statuses(self, client_id: str, tab_id: str = ''):
        client_items = [item for item in (self.catalog_service.get_catalog().get('items') or []) if item.get('side') == 'client' and not item.get('error')]
        return self.runtime_service.client_install_statuses(client_id, client_items, tab_id=tab_id)

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

    # Backward-compatible old method name.
    def install_and_run_client(self, client_id: str, tool_id: str, params=None, tab_id: str = ''):
        return self.runtime_service.install_and_run_client(client_id, tool_id, params=params, tab_id=tab_id)

    def uninstall_server_tool(self, tool_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.uninstall_server_tool(tool_id, params=params, instance_id=instance_id)

    def uninstall_client_tool(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = ''):
        return self.runtime_service.uninstall_client_tool(client_id, tool_id, params=params, tab_id=tab_id,
                                                          instance_id=instance_id)