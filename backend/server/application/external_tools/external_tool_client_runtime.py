from server.application.external_tools.external_tool_runtime_component import ExternalToolRuntimeComponent


class ExternalToolClientLifecycleRuntime(ExternalToolRuntimeComponent):
    """Client-targeted external tool lifecycle command dispatch."""

    def __init__(self, core, payload_builder):
        super().__init__(core)
        self.payload_builder = payload_builder

    def list_all_client_instances(self, client_id: str, metas: list[dict], tab_id: str = '') -> dict:
        tools = []
        errors = []
        for meta in metas or []:
            tool_id = str(meta.get('tool_id') or '').strip()
            if not tool_id:
                continue
            tools.append({'tool_id': tool_id, 'package_id': meta.get('package_id') or '', 'module_id': meta.get('id') or '', 'display_name': meta.get('display_name') or tool_id})
        payload = {'action': 'list_all', 'tools': tools, 'errors': errors}
        command = f'external_tool_list_instances_all {self.payload_builder.encode_payload_arg(payload)}'
        result = self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)
        if isinstance(result, dict):
            result.setdefault('side', 'client')
            result.setdefault('errors', errors)
            return result
        return result

    def _run_client_lifecycle_command(self, client_id: str, command: str, tab_id: str = '') -> dict:
        if self.remote_execution_service is None:
            return self.command_execution_api.submit_web_command(client_id, command, tab_id=tab_id)
        del tab_id
        return self.remote_execution_service.run_foreground_json_command(client_id, command, task_type='external_tool', source='web_external_tool')

    def start_client_instance(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', install_if_needed: bool = False, platform_alias: str = '', arch: str = '') -> dict:
        del install_if_needed
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_start_payload(meta, params=params, instance_id=instance_id, platform_alias=platform_alias, arch=arch)
        command = f'external_tool_start {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def run_client_oneshot(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_oneshot_payload(meta, params=params, platform_alias=platform_alias, arch=arch)
        command = f'external_tool_oneshot {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def install_client_tool(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.payload_builder.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'install'
        command = f'external_tool_install {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def client_install_status(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.payload_builder.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'install_status'
        command = f'external_tool_install_status {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def uninstall_client_tool(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.payload_builder.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'uninstall'
        command = f'external_tool_uninstall {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def client_install_statuses(self, client_id: str, packages: list[dict], tab_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        payload = {'action': 'install_statuses', 'tools': self.payload_builder.build_client_install_status_payloads(packages, platform_alias=platform_alias, arch=arch)}
        command = f'external_tool_install_statuses {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def clear_client_package_cache(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.payload_builder.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'clear_cache'
        command = f'external_tool_clear_cache {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def stop_client_instance(self, client_id: str, tool_id: str, instance_id: str, params: dict | None = None, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_action_payload(meta, 'stop', instance_id=instance_id, params=params)
        command = f'external_tool_stop {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def status_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_action_payload(meta, 'status', instance_id=instance_id)
        command = f'external_tool_status {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def list_client_instances(self, client_id: str, tool_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = {'action': 'list', 'tool_id': meta.get('tool_id') or '', 'package_id': meta.get('package_id') or '', 'module_id': meta.get('id') or '', 'display_name': meta.get('display_name') or meta.get('tool_id') or '', 'side': 'client'}
        command = f'external_tool_list_instances {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def read_client_logs(self, client_id: str, tool_id: str, instance_id: str, max_bytes: int | None = None, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_action_payload(meta, 'logs', instance_id=instance_id, max_bytes=max_bytes)
        command = f'external_tool_logs {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def remove_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_action_payload(meta, 'remove', instance_id=instance_id)
        command = f'external_tool_remove {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def clear_client_logs(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.payload_builder.build_client_action_payload(meta, 'clear_logs', instance_id=instance_id)
        command = f'external_tool_clear_logs {self.payload_builder.encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)
