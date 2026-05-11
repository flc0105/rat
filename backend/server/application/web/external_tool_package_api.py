class WebExternalToolPackageApi:
    def __init__(self, runtime_service):
        self.runtime_service = runtime_service

    def install_server_tool(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.package_runtime.install_server_tool(package_id, params=params, instance_id=instance_id)

    def server_install_status(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.package_runtime.server_install_status(package_id, params=params, instance_id=instance_id)

    def uninstall_server_tool(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.package_runtime.uninstall_server_tool(package_id, params=params, instance_id=instance_id)

    def clear_server_package_cache(self, package_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.package_runtime.clear_server_package_cache(package_id, params=params, instance_id=instance_id)
