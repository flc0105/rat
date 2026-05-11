import base64
import json
import logging
import os
import shlex

from core.external_tools.payload import (
    client_action_payload,
    client_exec_payload as build_shared_client_exec_payload,
    client_install_payload as build_shared_client_install_payload,
    client_module_payload as build_shared_client_module_payload,
    config_payload_from_rendered,
)


logger = logging.getLogger(__name__)


class ExternalToolClientRuntimeMixin:
    """Client-targeted external tool payload building and lifecycle command dispatch."""

    def list_all_client_instances(self, client_id: str, metas: list[dict], tab_id: str = '') -> dict:
        tools = []
        errors = []
        for meta in metas or []:
            tool_id = str(meta.get('tool_id') or '').strip()
            if not tool_id:
                continue
            tools.append({'tool_id': tool_id, 'package_id': meta.get('package_id') or '', 'module_id': meta.get('id') or '', 'display_name': meta.get('display_name') or tool_id})
        payload = {'action': 'list_all', 'tools': tools, 'errors': errors}
        command = f'external_tool_list_instances_all {self._encode_payload_arg(payload)}'
        result = self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)
        if isinstance(result, dict):
            result.setdefault('side', 'client')
            result.setdefault('errors', errors)
            return result
        return result



    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _client_download_url(self, filename: str, package_file: dict) -> str:
        download_url = str(package_file.get('download_url') or '').strip()
        if not download_url:
            download_url = f'/api/external-tools/packages/{filename}'
        return download_url

    def build_client_install_payload(self, package: dict, platform_alias: str, arch: str) -> dict:
        platform_value, arch_value = self._require_target(platform_alias, arch, f'client package {package.get("id") or "unknown"}')
        logger.info(
            '[external-tools] build client install payload: package_id=%s target=%s/%s',
            package.get('id') or '',
            platform_value,
            arch_value,
        )
        context = self.build_client_package_context(package, platform_alias=platform_value, arch=arch_value)
        package_file = self._package_file(package, context.get('package_key') or '')
        filename = str(package_file.get('filename') or '').strip()
        if not filename:
            raise ValueError('platform package filename is required')
        exec_name = self._primary_exec_name(package)
        rel_path = (context.get('exec') or {}).get(exec_name) or ''
        return build_shared_client_install_payload(
            package,
            context,
            source=self._package_source(package, context.get('package_key') or ''),
            filename=filename,
            download_url=self._client_download_url(filename, package_file),
            executable_rel_path=rel_path,
            skip_if_exists=self._client_skip_path(package, context),
            action='install',
        )

    def build_client_start_payload(self, meta: dict, params: dict | None = None, instance_id: str = '', install_if_needed: bool = False, require_required_params: bool = True, platform_alias: str = '', arch: str = '') -> dict:
        del install_if_needed
        package = meta.get('package_meta') or self.catalog_service.get_package(meta.get('package_id') or '')
        platform_value, arch_value = self._require_target(platform_alias, arch, f'client module {meta.get("tool_id") or meta.get("id") or "unknown"}')
        logger.info(
            '[external-tools] build client start payload: tool_id=%s target=%s/%s',
            meta.get('tool_id') or meta.get('id') or '',
            platform_value,
            arch_value,
        )
        resolved_params = self.resolve_params(meta, params, require_required=require_required_params)
        context = self.build_client_context(meta, resolved_params, instance_id=instance_id, platform_alias=platform_value, arch=arch_value)
        package_file = self._package_file(package, context.get('package_key') or '')
        filename = str(package_file.get('filename') or '').strip()
        if not filename:
            raise ValueError('platform package filename is required')
        rendered_meta = self._render_value(meta, context)
        runtime = self._render_value(self._module_runtime_for_platform(meta, context.get('platform') or '', context.get('arch') or ''), context)
        runtime.setdefault('state_file', context.get('state_file') or '')
        runtime_argv = runtime.get('argv') or []
        if isinstance(runtime_argv, str):
            runtime_argv = shlex.split(runtime_argv)
        if isinstance(runtime_argv, list):
            runtime['argv'] = self._append_runtime_extra_args(runtime_argv, runtime, context)
        config_payload = config_payload_from_rendered(rendered_meta, lambda value: self._render_value(value, context))
        exec_name = self._primary_exec_name(package, meta)
        rel_path = (context.get('exec') or {}).get(exec_name) or ''
        return build_shared_client_module_payload(
            meta,
            context,
            action='start',
            source=self._package_source(package, context.get('package_key') or ''),
            filename=filename,
            download_url=self._client_download_url(filename, package_file),
            executable_rel_path=rel_path,
            skip_if_exists=self._client_skip_path(package, context, module=meta),
            params=resolved_params,
            runtime=runtime,
            config=config_payload,
            lifecycle=rendered_meta.get('lifecycle') or {},
            install_if_needed=False,
        )

    def build_client_oneshot_payload(self, meta: dict, params: dict | None = None, platform_alias: str = '', arch: str = '') -> dict:
        if str(meta.get('execution') or '').strip().lower() != 'oneshot':
            raise ValueError(f'module {meta.get("tool_id") or meta.get("id") or "unknown"} execution is not oneshot')
        package = meta.get('package_meta') or self.catalog_service.get_package(meta.get('package_id') or '')
        platform_value, arch_value = self._require_target(platform_alias, arch, f'client oneshot {meta.get("tool_id") or meta.get("id") or "unknown"}')
        logger.info(
            '[external-tools] build client oneshot payload: tool_id=%s target=%s/%s',
            meta.get('tool_id') or meta.get('id') or '',
            platform_value,
            arch_value,
        )
        resolved_params = self.resolve_params(meta, params, require_required=True)
        run_id = self._make_oneshot_run_id(meta)
        context = self.build_client_context(meta, resolved_params, instance_id=run_id, platform_alias=platform_value, arch=arch_value)
        context = self._apply_client_oneshot_context(context, meta, run_id)
        package_file = self._package_file(package, context.get('package_key') or '')
        filename = str(package_file.get('filename') or '').strip()
        if not filename:
            raise ValueError('platform package filename is required')
        rendered_meta = self._render_value(meta, context)
        runtime = self._render_value(self._module_runtime_for_platform(meta, context.get('platform') or '', context.get('arch') or ''), context)
        runtime.setdefault('state_file', context.get('state_file') or '')
        runtime_argv = runtime.get('argv') or []
        if isinstance(runtime_argv, str):
            runtime_argv = shlex.split(runtime_argv)
        if isinstance(runtime_argv, list):
            runtime['argv'] = self._append_runtime_extra_args(runtime_argv, runtime, context)
        config_payload = config_payload_from_rendered(rendered_meta, lambda value: self._render_value(value, context))
        exec_name = self._primary_exec_name(package, meta)
        rel_path = (context.get('exec') or {}).get(exec_name) or ''
        return build_shared_client_module_payload(
            meta,
            context,
            action='oneshot',
            source=self._package_source(package, context.get('package_key') or ''),
            filename=filename,
            download_url=self._client_download_url(filename, package_file),
            executable_rel_path=rel_path,
            skip_if_exists=self._client_skip_path(package, context, module=meta),
            params=resolved_params,
            runtime=runtime,
            config=config_payload,
            install_if_needed=False,
            execution='oneshot',
            run_id=run_id,
            timeout_sec=self._oneshot_timeout_sec(meta, runtime),
        )

    def build_client_payload(self, meta: dict, params: dict | None = None) -> dict:
        return self.build_client_start_payload(meta, params=params)

    def build_client_action_payload(self, meta: dict, action: str, instance_id: str = '', params: dict | None = None, max_bytes: int | None = None) -> dict:
        resolved_params = self.resolve_params(meta, params or {}, require_required=False) if params else {}
        # Action payloads only need deterministic runtime path from package/module/instance.
        package_id = meta.get('package_id') or ''
        module_id = meta.get('id') or ''
        sanitized = self._sanitize_instance_id(instance_id)
        runtime_dir = os.path.join('~/.ops/external_tools/runtime', package_id, module_id, 'instances', sanitized)
        runtime = {'pid_file': os.path.join(runtime_dir, 'tool.pid'), 'stdout': os.path.join(runtime_dir, 'stdout.log'), 'stderr': 'stdout', 'state_file': os.path.join(runtime_dir, 'state.json')}
        return client_action_payload(
            meta,
            action=action,
            instance_id=sanitized,
            params=resolved_params,
            runtime=runtime,
            max_bytes=int(max_bytes or self.DEFAULT_LOG_TAIL_BYTES),
        )

    def build_client_install_status_payloads(self, packages: list[dict], platform_alias: str = '', arch: str = '') -> list[dict]:
        payloads = []
        for package in packages or []:
            try:
                payload = self.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
                payload['action'] = 'install_status'
                payloads.append(payload)
            except Exception as e:
                payloads.append({'action': 'install_status', 'tool_id': package.get('id') or '', 'package_id': package.get('id') or '', 'display_name': package.get('display_name') or package.get('id') or '', 'side': 'client', 'error': str(e)})
        return payloads

    def _run_client_lifecycle_command(self, client_id: str, command: str, tab_id: str = '') -> dict:
        if self.remote_execution_service is None:
            return self.command_execution_api.submit_web_command(client_id, command, tab_id=tab_id)
        del tab_id
        return self.remote_execution_service.run_foreground_json_command(client_id, command, task_type='external_tool', source='web_external_tool')

    def start_client_instance(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', install_if_needed: bool = False, platform_alias: str = '', arch: str = '') -> dict:
        del install_if_needed
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_start_payload(meta, params=params, instance_id=instance_id, platform_alias=platform_alias, arch=arch)
        command = f'external_tool_start {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def run_client_oneshot(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_oneshot_payload(meta, params=params, platform_alias=platform_alias, arch=arch)
        command = f'external_tool_oneshot {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def install_client_tool(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'install'
        command = f'external_tool_install {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def client_install_status(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'install_status'
        command = f'external_tool_install_status {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def uninstall_client_tool(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'uninstall'
        command = f'external_tool_uninstall {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def client_install_statuses(self, client_id: str, packages: list[dict], tab_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        payload = {'action': 'install_statuses', 'tools': self.build_client_install_status_payloads(packages, platform_alias=platform_alias, arch=arch)}
        command = f'external_tool_install_statuses {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def clear_client_package_cache(self, client_id: str, package_id: str, params: dict | None = None, tab_id: str = '', instance_id: str = '', platform_alias: str = '', arch: str = '') -> dict:
        del params, instance_id
        package = self.catalog_service.get_package(package_id)
        payload = self.build_client_install_payload(package, platform_alias=platform_alias, arch=arch)
        payload['action'] = 'clear_cache'
        command = f'external_tool_clear_cache {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def stop_client_instance(self, client_id: str, tool_id: str, instance_id: str, params: dict | None = None, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_action_payload(meta, 'stop', instance_id=instance_id, params=params)
        command = f'external_tool_stop {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def status_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_action_payload(meta, 'status', instance_id=instance_id)
        command = f'external_tool_status {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def list_client_instances(self, client_id: str, tool_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = {'action': 'list', 'tool_id': meta.get('tool_id') or '', 'package_id': meta.get('package_id') or '', 'module_id': meta.get('id') or '', 'display_name': meta.get('display_name') or meta.get('tool_id') or '', 'side': 'client'}
        command = f'external_tool_list_instances {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def read_client_logs(self, client_id: str, tool_id: str, instance_id: str, max_bytes: int | None = None, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_action_payload(meta, 'logs', instance_id=instance_id, max_bytes=max_bytes)
        command = f'external_tool_logs {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def remove_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_action_payload(meta, 'remove', instance_id=instance_id)
        command = f'external_tool_remove {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def clear_client_logs(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        payload = self.build_client_action_payload(meta, 'clear_logs', instance_id=instance_id)
        command = f'external_tool_clear_logs {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def build_client_exec_payload(self, target: dict, raw_args: str = '', platform_alias: str = '', arch: str = '', cwd: str = '') -> dict:
        package = target.get('package_meta') or {}
        exec_item = target.get('exec_item') if isinstance(target.get('exec_item'), dict) else {}
        exec_options = target.get('exec_options') if isinstance(target.get('exec_options'), dict) else {}
        exec_name = target.get('exec_name') or ''
        platform_value, arch_value = self._require_target(platform_alias, arch, f'client exec {exec_name or "unknown"}')
        logger.info(
            '[external-tools] build client exec payload: package_id=%s exec=%s target=%s/%s',
            package.get('id') or '',
            exec_name,
            platform_value,
            arch_value,
        )
        context = self.build_client_package_context(package, platform_alias=platform_value, arch=arch_value)
        package_file = self._package_file(package, context.get('package_key') or '')
        filename = str(package_file.get('filename') or '').strip()
        rel_path = self.catalog_service.resolve_exec_rel_path(package, exec_name, context.get('package_key') or '')
        return build_shared_client_exec_payload(
            package,
            context,
            source=self._package_source(package, context.get('package_key') or ''),
            filename=filename,
            download_url=self._client_download_url(filename, package_file),
            executable_rel_path=rel_path,
            skip_if_exists=self._client_skip_path(package, context),
            exec_name=exec_name,
            exec_options={
                'arg_mode': exec_options.get('arg_mode') or exec_item.get('arg_mode') or 'raw_append',
                'cwd': cwd or exec_options.get('cwd') or exec_item.get('cwd') or '',
                'timeout_sec': exec_options.get('timeout_sec') if exec_options.get('timeout_sec') is not None else exec_item.get('timeout_sec'),
            },
            raw_args=raw_args,
        )
