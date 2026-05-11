import os
import shutil


class ExternalToolPackageRuntimeMixin:
    """Server-side package install/status/uninstall operations."""

    def install_server_tool(self, package_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        context = self.build_server_package_context(package)
        install_info = self._install_package_if_needed(package, context)
        install_info['message'] = (
            f'{package.get("display_name") or package.get("id")} already installed at {install_info.get("install_dir")}'
            if install_info.get('already_installed')
            else f'{package.get("display_name") or package.get("id")} installed from local package file at {install_info.get("install_dir")}'
        )
        return install_info

    def server_install_status(self, package_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        context = self.build_server_package_context(package)
        status = self._build_install_status(package, context)
        status['message'] = (f'{package.get("display_name") or package.get("id")} is installed at {status.get("install_dir")}' if status.get('installed') else f'{package.get("display_name") or package.get("id")} is not installed. Please install it first.')
        return status

    def _has_running_server_instances_for_package(self, package_id: str) -> bool:
        package_runtime = self._safe_join_runtime(package_id)
        if not os.path.isdir(package_runtime):
            return False
        for module_id in os.listdir(package_runtime):
            instances_dir = os.path.join(package_runtime, module_id, 'instances')
            if not os.path.isdir(instances_dir):
                continue
            tool_id = f'{package_id}.{module_id}'
            try:
                meta = self.catalog_service.get_tool(tool_id)
            except Exception:
                continue
            for name in os.listdir(instances_dir):
                path = os.path.join(instances_dir, name)
                if os.path.isdir(path) and self._status_from_state(meta, name).get('running'):
                    return True
        return False

    def uninstall_server_tool(self, package_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        if self._has_running_server_instances_for_package(package.get('id') or ''):
            raise ValueError('This package has running instances on server. Stop them before uninstalling.')
        context = self.build_server_package_context(package)
        status = self._build_install_status(package, context)
        install_dir = status.get('install_dir') or ''
        removed = False
        if install_dir and os.path.isdir(install_dir):
            shutil.rmtree(install_dir)
            removed = True
        status.update({'installed': False, 'removed': removed, 'message': (f'{package.get("display_name") or package.get("id")} uninstalled from {install_dir}' if removed else f'{package.get("display_name") or package.get("id")} was not installed at {install_dir}')})
        return status

    def clear_server_package_cache(self, package_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        context = self.build_server_package_context(package)
        cache = self._local_package_file_info(package, context)
        return {
            'tool_id': package.get('id') or '',
            'package_id': package.get('id') or '',
            'display_name': package.get('display_name') or package.get('id') or '',
            'side': 'server',
            'platform': context.get('platform') or '',
            'arch': context.get('arch') or '',
            'package_key': context.get('package_key') or '',
            'cache': cache,
            'cache_removed': False,
            'removed': False,
            'message': 'Server packages are served from local resources; no server package cache was removed.',
        }

