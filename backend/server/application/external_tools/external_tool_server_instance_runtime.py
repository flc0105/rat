import logging
import os
import shutil

from core.external_tools.files import tail_text_file


logger = logging.getLogger(__name__)


class ExternalToolServerInstanceRuntimeMixin:
    """Server-side daemon and oneshot instance lifecycle operations."""

    def start_server_instance(self, tool_id: str, params: dict | None = None, instance_id: str = '', install_if_needed: bool = False) -> dict:
        del install_if_needed
        meta = self.catalog_service.get_tool(tool_id)
        package = meta.get('package_meta') or self.catalog_service.get_package(meta.get('package_id') or '')
        resolved_params = self.resolve_params(meta, params)
        context = self.build_server_context(meta, resolved_params, instance_id=instance_id)
        instance_id = context['instance_id']
        os.makedirs(context['instance_runtime_dir'], exist_ok=True)
        install_info = self._build_install_status(package, context, module=meta)
        if not install_info.get('installed'):
            raise ValueError('Package is not installed. Please install it first.')
        install_info.update({'already_installed': True, 'extracted': False, 'message': 'using existing installation'})
        for path in (context.get('bin') or {}).values():
            self._chmod_executable(path)
        config_info = self._write_config(meta, context)
        runtime_spec = self._build_runtime_spec(meta, context)
        existing_pid = self._read_pid_file(runtime_spec['pid_file'])
        if self._is_pid_alive(existing_pid):
            status = self._status_from_state(meta, instance_id)
            status['message'] = f'{meta.get("display_name") or meta.get("tool_id")} instance {instance_id} is already running'
            return status
        process = self._start_detached_process(runtime_spec)
        state_file = self._write_state_file(meta, context, runtime_spec, process, install_info, config_info, resolved_params)
        return {'tool_id': meta.get('tool_id') or '', 'package_id': meta.get('package_id') or '', 'module_id': meta.get('id') or '', 'side': 'server', 'instance_id': instance_id, 'status': 'running', 'running': True, 'pid': process.pid, 'install': install_info, 'config': config_info, 'runtime': runtime_spec, 'state_file': state_file, 'message': f'{meta.get("display_name") or meta.get("tool_id")} instance {instance_id} started on server'}

    def run_server_oneshot(self, tool_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        del instance_id
        meta = self.catalog_service.get_tool(tool_id)
        if str(meta.get('execution') or '').strip().lower() != 'oneshot':
            raise ValueError(f'module {tool_id} execution is not oneshot')
        package = meta.get('package_meta') or self.catalog_service.get_package(meta.get('package_id') or '')
        resolved_params = self.resolve_params(meta, params)
        run_id = self._make_oneshot_run_id(meta)
        context = self.build_server_context(meta, resolved_params, instance_id=run_id)
        context = self._apply_server_oneshot_context(context, meta, run_id)
        os.makedirs(context['instance_runtime_dir'], exist_ok=True)
        install_info = self._build_install_status(package, context, module=meta)
        if not install_info.get('installed'):
            raise ValueError('Package is not installed. Please install it first.')
        install_info.update({'already_installed': True, 'extracted': False, 'message': 'using existing installation'})
        for path in (context.get('bin') or {}).values():
            self._chmod_executable(path)
        config_info = self._write_config(meta, context)
        runtime_spec = self._build_runtime_spec(meta, context)
        timeout_sec = self._oneshot_timeout_sec(meta, self._module_runtime_for_platform(meta, context.get('platform') or '', context.get('arch') or ''))
        logger.info(
            '[external-tools] run server oneshot: tool_id=%s run_id=%s timeout=%s argv=%s',
            meta.get('tool_id') or tool_id,
            run_id,
            timeout_sec,
            runtime_spec.get('argv') or [],
        )
        run_result = self._run_foreground_process(runtime_spec, timeout_sec=timeout_sec)
        success = run_result.get('returncode') == 0 and not run_result.get('timed_out')
        return {
            'tool_id': meta.get('tool_id') or '',
            'package_id': meta.get('package_id') or '',
            'module_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('tool_id') or '',
            'execution': 'oneshot',
            'side': 'server',
            'run_id': run_id,
            'status': 'completed' if success else 'failed',
            'success': success,
            'running': False,
            'returncode': run_result.get('returncode'),
            'stdout': run_result.get('stdout') or '',
            'stderr': run_result.get('stderr') or '',
            'timed_out': bool(run_result.get('timed_out')),
            'started_at': run_result.get('started_at') or '',
            'finished_at': run_result.get('finished_at') or '',
            'duration_sec': run_result.get('duration_sec'),
            'install': install_info,
            'config': config_info,
            'runtime': runtime_spec,
            'params': resolved_params,
            'message': f'{meta.get("display_name") or meta.get("tool_id")} completed on server' if success else f'{meta.get("display_name") or meta.get("tool_id")} failed on server',
        }

    def stop_server_instance(self, tool_id: str, instance_id: str, params: dict | None = None) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        instance_id = self._sanitize_instance_id(instance_id)
        status_before = self._status_from_state(meta, instance_id)
        pid = status_before.get('pid')
        info = self._state_or_default_runtime(meta, instance_id)
        stop_spec = self._resolve_stop_lifecycle(meta)
        context = self.build_server_context(meta, params or {}, instance_id=instance_id)
        context.update({'pid': pid or '', 'pid_file': info['runtime']['pid_file'], 'stdout': info['runtime'].get('stdout') or '', 'state_file': info['state_file']})
        if str(stop_spec.get('type') or 'signal').strip().lower() == 'command':
            result = self._run_lifecycle_command(stop_spec, context)
            fallback = stop_spec.get('fallback') if isinstance(stop_spec.get('fallback'), dict) else None
            if fallback and self._is_pid_alive(pid):
                result['fallback'] = self._stop_by_signal(pid, fallback)
        else:
            result = self._stop_by_signal(pid, stop_spec)
        if not self._is_pid_alive(pid):
            try:
                if os.path.exists(info['runtime']['pid_file']):
                    os.unlink(info['runtime']['pid_file'])
            except OSError:
                pass
            self._mark_stopped(info['state_file'], result)
        status_after = self._status_from_state(meta, instance_id)
        status_after['stop_result'] = result
        status_after['message'] = f'{meta.get("display_name") or meta.get("tool_id")} instance {instance_id} stop requested'
        return status_after

    def status_server_instance(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        return self._status_from_state(meta, self._sanitize_instance_id(instance_id))

    def list_server_instances(self, tool_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        tool_runtime = self._safe_join_runtime(meta.get('package_id') or '', meta.get('id') or '', 'instances')
        items = []
        if os.path.isdir(tool_runtime):
            for name in sorted(os.listdir(tool_runtime)):
                path = os.path.join(tool_runtime, name)
                if os.path.isdir(path):
                    items.append(self._status_from_state(meta, name))
        return {'tool_id': meta.get('tool_id') or '', 'side': 'server', 'items': items}

    def list_all_server_instances(self, metas: list[dict]) -> dict:
        items = []
        by_tool = {}
        errors = []
        for meta in metas or []:
            tool_id = str(meta.get('tool_id') or '').strip()
            if not tool_id:
                continue
            tool_items = []
            by_tool[tool_id] = tool_items
            try:
                tool_runtime = self._safe_join_runtime(meta.get('package_id') or '', meta.get('id') or '', 'instances')
                if os.path.isdir(tool_runtime):
                    for name in sorted(os.listdir(tool_runtime)):
                        path = os.path.join(tool_runtime, name)
                        if not os.path.isdir(path):
                            continue
                        row = self._status_from_state(meta, name)
                        tool_items.append(row)
                        items.append(row)
            except Exception as e:
                errors.append({'tool_id': tool_id, 'message': str(e)})
        return {'side': 'server', 'items': items, 'by_tool': by_tool, 'errors': errors}

    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes: int | None = None) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        instance_id = self._sanitize_instance_id(instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        log_file = info['runtime'].get('stdout') or os.path.join(info['instance_runtime_dir'], 'stdout.log')
        max_bytes = int(max_bytes or self.DEFAULT_LOG_TAIL_BYTES)
        content = tail_text_file(log_file, max_bytes)
        return {'tool_id': meta.get('tool_id') or '', 'instance_id': instance_id, 'log_file': log_file, 'content': content, 'max_bytes': max_bytes}

    def remove_server_instance(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        instance_id = self._sanitize_instance_id(instance_id)
        status = self._ensure_server_instance_stopped(meta, instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        runtime_dir = self._expand_path(info.get('instance_runtime_dir') or '')
        if runtime_dir and os.path.isdir(runtime_dir):
            shutil.rmtree(runtime_dir)
        return {'tool_id': meta.get('tool_id') or '', 'side': 'server', 'instance_id': instance_id, 'removed': True, 'runtime_dir': runtime_dir, 'previous_status': status, 'message': f'{meta.get("display_name") or meta.get("tool_id")} instance {instance_id} runtime removed'}

    def clear_server_logs(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        instance_id = self._sanitize_instance_id(instance_id)
        status = self._ensure_server_instance_stopped(meta, instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        log_file = self._expand_path(info['runtime'].get('stdout') or os.path.join(info['instance_runtime_dir'], 'stdout.log'))
        if os.path.isfile(log_file):
            with open(log_file, 'w', encoding='utf-8'):
                pass
        return {'tool_id': meta.get('tool_id') or '', 'side': 'server', 'instance_id': instance_id, 'cleared': True, 'log_file': log_file, 'previous_status': status, 'message': f'{meta.get("display_name") or meta.get("tool_id")} instance {instance_id} logs cleared'}
