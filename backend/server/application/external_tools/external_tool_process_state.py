import os
import shlex
import subprocess
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from core.external_tools.files import read_json_file, write_json_file
from core.external_tools.processes import (
    is_pid_alive,
    read_pid_file,
    run_foreground_process,
    signal_name_to_value,
    signal_process_group_or_pid,
    start_detached_process,
    stop_by_signal,
    write_stopped_state,
)


class ExternalToolProcessStateMixin:
    """Foreground process, daemon state and stop lifecycle helpers."""

    def _run_foreground_process(self, runtime_spec: dict, timeout_sec: float | None = None) -> dict:
        return run_foreground_process(runtime_spec, timeout_sec=timeout_sec)
    def _oneshot_timeout_sec(self, meta: dict, runtime: dict | None = None) -> float | None:
        source = runtime if isinstance(runtime, dict) else {}
        oneshot = meta.get('oneshot') if isinstance(meta.get('oneshot'), dict) else {}
        raw = source.get('timeout_sec', oneshot.get('timeout_sec', meta.get('timeout_sec', 60)))
        if raw in ('', None):
            return None
        try:
            value = float(raw)
        except Exception:
            raise ValueError(f'invalid oneshot timeout_sec: {raw}')
        if value <= 0:
            raise ValueError(f'invalid oneshot timeout_sec: {raw}')
        return value
    def _make_oneshot_run_id(self, meta: dict) -> str:
        prefix = self._sanitize_instance_id(meta.get('name') or meta.get('id') or 'oneshot')
        return f'{prefix}-{datetime.now().strftime("%Y%m%d-%H%M%S-%f")}'[:96]
    def _apply_server_oneshot_context(self, context: dict, meta: dict, run_id: str) -> dict:
        package_id = str(meta.get('package_id') or '').strip()
        module_id = str(meta.get('id') or meta.get('module_id') or '').strip()
        run_dir = self._expand_path(os.path.join(self.runtime_root_dir, package_id, module_id, 'oneshot', run_id))
        context['run_id'] = run_id
        context['instance_id'] = ''
        context['instance_name'] = ''
        context['instance_runtime_dir'] = run_dir
        context['state_file'] = os.path.join(run_dir, 'result.json')
        return context
    def _apply_client_oneshot_context(self, context: dict, meta: dict, run_id: str) -> dict:
        package_id = str(meta.get('package_id') or '').strip()
        module_id = str(meta.get('id') or meta.get('module_id') or '').strip()
        run_dir = os.path.join('~/.ops/external_tools/runtime', package_id, module_id, 'oneshot', run_id).replace('\\', '/')
        context['run_id'] = run_id
        context['instance_id'] = ''
        context['instance_name'] = ''
        context['instance_runtime_dir'] = run_dir
        context['state_file'] = os.path.join(run_dir, 'result.json').replace('\\', '/')
        return context
    def _start_detached_process(self, runtime_spec: dict):
        return start_detached_process(runtime_spec)
    def _read_pid_file(self, pid_file: str) -> int | None:
        return read_pid_file(pid_file)
    def _is_pid_alive(self, pid: int | None) -> bool:
        return is_pid_alive(pid)
    def _signal_process_group_or_pid(self, pid: int, sig: int):
        signal_process_group_or_pid(pid, sig)
    def _read_json_file(self, path: str) -> dict:
        return read_json_file(path)
    def _write_json_file(self, path: str, data: dict):
        write_json_file(path, data)
    def _default_instance_runtime_dir(self, tool_id: str, instance_id: str) -> str:
        meta = self.catalog_service.get_tool(tool_id)
        return self._safe_join_runtime(meta.get('package_id') or '', meta.get('id') or '', 'instances', self._sanitize_instance_id(instance_id))
    def _state_path_for(self, tool_id: str, instance_id: str) -> str:
        return os.path.join(self._default_instance_runtime_dir(tool_id, instance_id), 'state.json')
    def _state_or_default_runtime(self, meta: dict, instance_id: str) -> dict:
        tool_id = str(meta.get('tool_id') or '').strip()
        state_file = self._state_path_for(tool_id, instance_id)
        state = self._read_json_file(state_file) if os.path.isfile(state_file) else {}
        runtime = state.get('runtime') if isinstance(state.get('runtime'), dict) else {}
        instance_runtime_dir = self._default_instance_runtime_dir(tool_id, instance_id)
        pid_file = runtime.get('pid_file') or state.get('pid_file') or os.path.join(instance_runtime_dir, 'tool.pid')
        stdout = runtime.get('stdout') or state.get('stdout') or os.path.join(instance_runtime_dir, 'stdout.log')
        stderr = runtime.get('stderr') or state.get('stderr') or 'stdout'
        return {
            'state': state,
            'state_file': state_file,
            'runtime': {
                'pid_file': self._expand_path(pid_file),
                'stdout': self._expand_path(stdout),
                'stderr': self._expand_path(stderr) if stderr != 'stdout' else 'stdout',
                'state_file': state_file,
                'cwd': runtime.get('cwd') or state.get('cwd') or '',
                'argv': runtime.get('argv') or state.get('argv') or [],
            },
            'instance_runtime_dir': instance_runtime_dir,
        }
    def _status_from_state(self, meta: dict, instance_id: str) -> dict:
        info = self._state_or_default_runtime(meta, instance_id)
        runtime = info['runtime']
        state = info['state']
        pid = self._read_pid_file(runtime['pid_file'])
        alive = self._is_pid_alive(pid)
        if alive:
            status = 'running'
        elif os.path.exists(runtime['pid_file']):
            status = 'stale'
        elif state:
            status = state.get('last_status') or 'stopped'
        else:
            status = 'not_started'
        return {
            'tool_id': meta.get('tool_id') or '',
            'package_id': meta.get('package_id') or state.get('package_id') or '',
            'module_id': meta.get('id') or state.get('module_id') or '',
            'display_name': meta.get('display_name') or meta.get('tool_id') or '',
            'side': state.get('side') or '',
            'instance_id': self._sanitize_instance_id(instance_id),
            'status': status,
            'running': alive,
            'pid': pid,
            'pid_file': runtime['pid_file'],
            'state_file': info['state_file'],
            'stdout': runtime.get('stdout') or '',
            'stderr': runtime.get('stderr') or '',
            'runtime': runtime,
            'config': state.get('config') or {},
            'params': state.get('params') or {},
            'install': state.get('install') or {},
            'argv': state.get('argv') or runtime.get('argv') or [],
            'cwd': state.get('cwd') or runtime.get('cwd') or '',
            'started_at': state.get('started_at') or '',
            'stopped_at': state.get('stopped_at') or '',
            'message': state.get('message') or '',
        }
    def _write_state_file(self, meta: dict, context: dict, runtime_spec: dict, process: SimpleNamespace, install_info: dict, config_info: dict, params: dict) -> str:
        state_file = runtime_spec.get('state_file') or context.get('state_file') or os.path.join(os.path.dirname(runtime_spec['pid_file']), 'state.json')
        payload = {
            'tool_id': meta.get('tool_id') or '',
            'package_id': meta.get('package_id') or '',
            'module_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or '',
            'version': meta.get('version') or '',
            'side': context.get('side') or '',
            'platform': context.get('platform') or '',
            'arch': context.get('arch') or '',
            'package_key': context.get('package_key') or '',
            'instance_id': context.get('instance_id') or 'default',
            'instance_name': context.get('instance_name') or context.get('instance_id') or 'default',
            'pid': process.pid,
            'params': params or {},
            'install': install_info or {},
            'config': config_info or {},
            'runtime': runtime_spec or {},
            'argv': runtime_spec.get('argv') or [],
            'cwd': runtime_spec.get('cwd') or '',
            'stdout': runtime_spec.get('stdout') or '',
            'stderr': runtime_spec.get('stderr') or '',
            'pid_file': runtime_spec.get('pid_file') or '',
            'state_file': state_file,
            'install_dir': install_info.get('install_dir') or '',
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'last_status': 'running',
        }
        self._write_json_file(state_file, payload)
        return state_file
    def _resolve_stop_lifecycle(self, meta: dict) -> dict:
        lifecycle = meta.get('lifecycle') if isinstance(meta.get('lifecycle'), dict) else {}
        stop = lifecycle.get('stop') if isinstance(lifecycle.get('stop'), dict) else {}
        if not stop:
            stop = {'type': 'signal', 'signal': 'TERM', 'timeout_sec': self.DEFAULT_STOP_TIMEOUT_SEC, 'kill_after_timeout': True}
        return stop
    def _signal_name_to_value(self, value: Any) -> int:
        return signal_name_to_value(value)
    def _run_lifecycle_command(self, stop_spec: dict, context: dict) -> dict:
        argv = stop_spec.get('argv') or stop_spec.get('command') or []
        rendered = self._render_value(argv, context)
        if isinstance(rendered, str):
            rendered = shlex.split(rendered)
        if not isinstance(rendered, list) or not rendered:
            raise ValueError('lifecycle.stop.argv is required for command stop')
        rendered = [self._expand_path(str(item)) if self._should_expand_argv_item(str(item), index) else str(item) for index, item in enumerate(rendered)]
        timeout = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)
        completed = subprocess.run(rendered, cwd=self._expand_path(self._render_value(stop_spec.get('cwd') or context.get('instance_runtime_dir') or '.', context)), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=max(1, timeout), close_fds=True)
        return {'type': 'command', 'argv': rendered, 'returncode': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr}
    def _stop_by_signal(self, pid: int | None, stop_spec: dict) -> dict:
        return stop_by_signal(pid, stop_spec, default_timeout_sec=self.DEFAULT_STOP_TIMEOUT_SEC)
    def _mark_stopped(self, state_file: str, stop_result: dict):
        write_stopped_state(state_file, stop_result, datetime.now().isoformat(timespec='seconds'))
    def _ensure_server_instance_stopped(self, meta: dict, instance_id: str) -> dict:
        status = self._status_from_state(meta, instance_id)
        if status.get('running'):
            raise ValueError('Stop this instance before modifying runtime files.')
        return status
