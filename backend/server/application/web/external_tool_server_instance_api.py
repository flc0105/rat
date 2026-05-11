class WebExternalToolServerInstanceApi:
    def __init__(self, catalog_service, runtime_service):
        self.catalog_service = catalog_service
        self.runtime_service = runtime_service

    def start_server_instance(self, tool_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.server_instance_runtime.start_server_instance(tool_id, params=params, instance_id=instance_id, install_if_needed=False)

    def run_server_oneshot(self, tool_id: str, params=None):
        return self.runtime_service.server_instance_runtime.run_server_oneshot(tool_id, params=params)

    def stop_server_instance(self, tool_id: str, instance_id: str, params=None):
        return self.runtime_service.server_instance_runtime.stop_server_instance(tool_id, instance_id=instance_id, params=params)

    def status_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.server_instance_runtime.status_server_instance(tool_id, instance_id=instance_id)

    def list_server_instances(self, tool_id: str):
        return self.runtime_service.server_instance_runtime.list_server_instances(tool_id)

    def list_all_server_instances(self):
        modules = [item for item in (self.catalog_service.get_catalog().get('modules') or []) if not item.get('error')]
        return self.runtime_service.server_instance_runtime.list_all_server_instances(modules)

    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes=None):
        return self.runtime_service.server_instance_runtime.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)

    def remove_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.server_instance_runtime.remove_server_instance(tool_id, instance_id=instance_id)

    def clear_server_logs(self, tool_id: str, instance_id: str):
        return self.runtime_service.server_instance_runtime.clear_server_logs(tool_id, instance_id=instance_id)
