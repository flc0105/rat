import base64
import errno
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from core.platform.platform_identity import detect_platform_alias


_VAR_PATTERN = re.compile(r'{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}')
_INSTANCE_PATTERN = re.compile(r'[^A-Za-z0-9_.-]+')


class ExternalToolRuntimeService:
    """
    External tool lifecycle runtime.

    Server-side tools are installed and started directly on the server.
    Client-side tools are rendered into deterministic payloads and executed by
    the selected client through the existing foreground command channel.

    Important:
    - install_dir is shared by tool/version.
    - instance_runtime_dir is per tool/instance and owns config/log/pid/state.
    - install status must not require runtime params.
    - client socket can only run one command at a time, so batch status is used.
    """

    DEFAULT_STOP_TIMEOUT_SEC = 5
    DEFAULT_LOG_TAIL_BYTES = 65536

    def __init__(
        self,
        catalog_service,
        command_execution_api,
        install_root_dir: str,
        runtime_root_dir: str,
        remote_execution_service=None,
    ):
        self.catalog_service = catalog_service
        self.command_execution_api = command_execution_api
        self.remote_execution_service = remote_execution_service
        self.install_root_dir = os.path.abspath(install_root_dir)
        self.runtime_root_dir = os.path.abspath(runtime_root_dir)
        os.makedirs(self.install_root_dir, exist_ok=True)
        os.makedirs(self.runtime_root_dir, exist_ok=True)

    def _normalize_arch(self, value: str = '') -> str:
        text = str(value or platform.machine() or '').strip().lower().replace('-', '_')
        aliases = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'i386': '386',
            'i686': '386',
            'aarch64': 'arm64',
            'arm64': 'arm64',
        }
        return aliases.get(text, text)

    def _meta_sides(self, meta: dict) -> list[str]:
        raw = meta.get('sides')
        if raw is None:
            raw = meta.get('side')

        if isinstance(raw, list):
            source = raw
        elif isinstance(raw, tuple):
            source = list(raw)
        else:
            source = [raw]

        sides = []
        seen = set()
        for item in source:
            side = str(item or '').strip().lower()
            if side not in ('server', 'client') or side in seen:
                continue
            seen.add(side)
            sides.append(side)
        return sides or ['client']

    def _meta_primary_side(self, meta: dict) -> str:
        return self._meta_sides(meta)[0]

    def _meta_supports_side(self, meta: dict, side: str) -> bool:
        return str(side or '').strip().lower() in self._meta_sides(meta)

    def _render_value(self, value: Any, context: dict) -> Any:
        if isinstance(value, str):
            def replace(match):
                key = match.group(1)
                return str(context.get(key, match.group(0)))

            return _VAR_PATTERN.sub(replace, value)

        if isinstance(value, list):
            return [self._render_value(item, context) for item in value]

        if isinstance(value, dict):
            return {key: self._render_value(val, context) for key, val in value.items()}

        return value

    def _expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def _is_url_like(self, value: str) -> bool:
        text = str(value or '').strip().lower()
        if '://' not in text:
            return False
        scheme = text.split('://', 1)[0]
        return bool(scheme) and all(ch.isalnum() or ch in '+-.' for ch in scheme)

    def _should_expand_argv_item(self, value: str, index: int) -> bool:
        text = str(value or '').strip()
        if not text:
            return False
        if self._is_url_like(text):
            return False
        if index == 0:
            return True
        return (
            text.startswith('~')
            or text.startswith('/')
            or text.startswith('./')
            or text.startswith('../')
            or text.startswith('.\\')
            or text.startswith('..\\')
            or ('\\' in text)
        )

    def _safe_join_runtime(self, *parts: str) -> str:
        path = os.path.abspath(os.path.join(self.runtime_root_dir, *[str(part or '') for part in parts]))
        if os.path.commonpath([self.runtime_root_dir, path]) != self.runtime_root_dir:
            raise ValueError('invalid runtime path')
        return path

    def _sanitize_instance_id(self, value: Any) -> str:
        text = str(value or '').strip()
        text = _INSTANCE_PATTERN.sub('-', text).strip('.-_')
        if not text:
            text = 'default'
        return text[:96]

    def _derive_instance_id(self, meta: dict, params: dict | None, explicit: str = '') -> str:
        params = params if isinstance(params, dict) else {}

        raw = explicit or params.get('instance_id') or params.get('instance_name')
        if not raw:
            proxy_name = str(params.get('proxy_name') or '').strip()
            remote_port = str(params.get('remote_port') or '').strip()
            bind_port = str(params.get('bind_port') or '').strip()

            if proxy_name and remote_port:
                raw = f'{proxy_name}-{remote_port}'
            elif bind_port:
                raw = f'{meta.get("name") or meta.get("id")}-{bind_port}'
            else:
                raw = 'default'

        return self._sanitize_instance_id(raw)

    def _coerce_param_value(self, spec: dict, value: Any, require_required: bool = True) -> Any:
        param_type = str(spec.get('type') or 'string').strip().lower()

        if value is None or value == '':
            if spec.get('default') is not None:
                value = spec.get('default')
            elif spec.get('required') and require_required:
                raise ValueError(f'param {spec.get("name")} is required')
            else:
                return ''

        if param_type in ('int', 'integer', 'number'):
            try:
                return int(value)
            except Exception:
                raise ValueError(f'param {spec.get("name")} must be an integer')

        if param_type in ('bool', 'boolean'):
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ('1', 'true', 'yes', 'on')

        return str(value)

    def resolve_params(self, meta: dict, params: dict | None, require_required: bool = True) -> dict:
        source = params if isinstance(params, dict) else {}
        resolved = {}

        for spec in meta.get('params') or []:
            name = str(spec.get('name') or '').strip()
            if not name:
                continue
            resolved[name] = self._coerce_param_value(
                spec,
                source.get(name),
                require_required=require_required,
            )

        for key, value in source.items():
            if key not in resolved:
                resolved[key] = value

        return resolved

    def _base_context(
        self,
        meta: dict,
        params: dict,
        *,
        install_root: str,
        runtime_root: str,
        instance_id: str = '',
        side: str = '',
    ) -> dict:
        params = params if isinstance(params, dict) else {}

        version = str(meta.get('version') or 'default').strip() or 'default'
        resolved_instance_id = self._derive_instance_id(meta, params, explicit=instance_id)
        resolved_side = str(side or self._meta_primary_side(meta)).strip().lower()
        tool_id = str(meta.get('id') or '').strip()
        tool_runtime_dir = os.path.join(runtime_root, tool_id)
        instance_runtime_dir = os.path.join(tool_runtime_dir, 'instances', resolved_instance_id)

        context = {
            'id': tool_id,
            'name': str(meta.get('name') or meta.get('id') or '').strip(),
            'display_name': str(meta.get('display_name') or meta.get('id') or '').strip(),
            'version': version,
            'side': resolved_side,
            'platform': detect_platform_alias(),
            'arch': self._normalize_arch(),
            'external_tools_root': install_root,
            'external_tools_runtime': runtime_root,
            'runtime_dir': runtime_root,
            'tool_runtime_dir': tool_runtime_dir,
            'instance_id': resolved_instance_id,
            'instance_name': params.get('instance_name') or resolved_instance_id,
            'instance_runtime_dir': instance_runtime_dir,
            'state_file': os.path.join(instance_runtime_dir, 'state.json'),
        }

        context.update(params or {})
        context['instance_id'] = resolved_instance_id
        context['instance_runtime_dir'] = instance_runtime_dir
        context['state_file'] = os.path.join(instance_runtime_dir, 'state.json')

        install_template = str((meta.get('install') or {}).get('install_dir') or '{{external_tools_root}}/{{id}}/{{version}}')
        install_dir = self._render_value(install_template, context)
        context['install_dir'] = install_dir

        return context

    def build_server_context(self, meta: dict, params: dict, instance_id: str = '') -> dict:
        context = self._base_context(
            meta,
            params,
            install_root=self.install_root_dir,
            runtime_root=self.runtime_root_dir,
            instance_id=instance_id,
            side='server',
        )

        for key in (
            'external_tools_root',
            'external_tools_runtime',
            'runtime_dir',
            'tool_runtime_dir',
            'instance_runtime_dir',
            'state_file',
            'install_dir',
        ):
            context[key] = self._expand_path(context[key])

        return context

    def build_client_context(self, meta: dict, params: dict, instance_id: str = '') -> dict:
        return self._base_context(
            meta,
            params,
            install_root='~/.ops/external_tools/installed',
            runtime_root='~/.ops/external_tools/runtime',
            instance_id=instance_id,
            side='client',
        )

    def _assert_tool_usable(self, meta: dict, side: str, platform_alias: str = ''):
        side = str(side or '').strip().lower()
        supported_sides = self._meta_sides(meta)
        if side not in supported_sides:
            raise ValueError(f'{meta.get("id")} supports {"/".join(supported_sides)}, not {side}')

        target_platform = platform_alias or detect_platform_alias()
        if target_platform == '*':
            return

        platforms = meta.get('platforms') or []
        if platforms and '*' not in platforms and target_platform not in platforms:
            raise ValueError(f'{meta.get("id")} does not support platform {target_platform}')

    def _safe_extract_zip(self, zip_path: str, destination_dir: str) -> str:
        destination_dir = self._expand_path(destination_dir)
        os.makedirs(destination_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as archive:
            for member in archive.infolist():
                member_path = os.path.abspath(os.path.join(destination_dir, member.filename))
                if os.path.commonpath([destination_dir, member_path]) != destination_dir:
                    raise ValueError(f'Unsafe zip entry detected: {member.filename}')
            archive.extractall(destination_dir)

        return destination_dir

    def _chmod_executable(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return

        current_mode = os.stat(path).st_mode
        os.chmod(path, current_mode | 0o111)

    def _resolve_skip_path(self, meta: dict, context: dict) -> str:
        install = meta.get('install') or {}
        skip_template = str(install.get('skip_if_exists') or '').strip()

        if not skip_template:
            executable_rel_path = str((meta.get('package') or {}).get('executable_rel_path') or '').strip()
            skip_template = '{{install_dir}}/' + executable_rel_path if executable_rel_path else '{{install_dir}}'

        return self._expand_path(self._render_value(skip_template, context))

    def _build_install_status(self, meta: dict, context: dict) -> dict:
        install_dir = self._expand_path(self._render_value('{{install_dir}}', context))
        context['install_dir'] = install_dir

        skip_path = self._resolve_skip_path(meta, context)
        executable_rel_path = str((meta.get('package') or {}).get('executable_rel_path') or '').strip()
        executable_path = self._expand_path(os.path.join(install_dir, executable_rel_path)) if executable_rel_path else skip_path
        installed = os.path.exists(skip_path)

        return {
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'side': context.get('side') or self._meta_primary_side(meta),
            'installed': installed,
            'install_dir': install_dir,
            'skip_path': skip_path,
            'executable_path': executable_path,
            'command': shlex.quote(executable_path),
        }

    def _install_package_if_needed(self, meta: dict, context: dict) -> dict:
        status = self._build_install_status(meta, context)
        install_dir = status['install_dir']
        skip_path = status['skip_path']
        already_installed = bool(status['installed'])
        extracted = False

        if not already_installed:
            package = meta.get('package') or {}
            filename = str(package.get('filename') or '').strip()
            if not filename:
                raise ValueError('package.filename is required')

            package_path = self.catalog_service.get_package_path(filename)
            os.makedirs(install_dir, exist_ok=True)
            self._safe_extract_zip(package_path, install_dir)
            extracted = True

        executable_path = status['executable_path']
        self._chmod_executable(executable_path)

        status.update({
            'installed': True,
            'already_installed': already_installed,
            'extracted': extracted,
            'message': 'already installed' if already_installed else 'installed successfully',
        })

        return status

    def _write_config(self, meta: dict, context: dict) -> dict:
        config = meta.get('config') or {}
        target_template = str(config.get('target') or '').strip()
        template = config.get('template')

        if not target_template or template is None:
            return {}

        target = self._expand_path(self._render_value(target_template, context))
        content = self._render_value(str(template), context)

        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'w', encoding='utf-8') as file_obj:
            file_obj.write(content)

        return {'target': target, 'size': os.path.getsize(target)}

    def _build_runtime_spec(self, meta: dict, context: dict) -> dict:
        runtime = self._render_value(meta.get('runtime') or {}, context)
        argv = runtime.get('argv') or []

        if isinstance(argv, str):
            argv = shlex.split(argv)

        if not isinstance(argv, list) or not argv:
            raise ValueError('runtime.argv is required')

        argv = [
            self._expand_path(str(item))
            if self._should_expand_argv_item(str(item), index)
            else str(item)
            for index, item in enumerate(argv)
        ]

        cwd = self._expand_path(runtime.get('cwd') or context.get('install_dir') or '.')
        stdout = self._expand_path(runtime.get('stdout') or os.path.join(context['instance_runtime_dir'], 'stdout.log'))
        stderr = runtime.get('stderr') or 'stdout'

        if stderr != 'stdout':
            stderr = self._expand_path(stderr)

        pid_file = self._expand_path(runtime.get('pid_file') or os.path.join(context['instance_runtime_dir'], 'tool.pid'))
        state_file = self._expand_path(runtime.get('state_file') or context.get('state_file') or os.path.join(os.path.dirname(pid_file), 'state.json'))

        return {
            'argv': argv,
            'cwd': cwd,
            'stdout': stdout,
            'stderr': stderr,
            'pid_file': pid_file,
            'state_file': state_file,
        }

    def _start_detached_process(self, runtime_spec: dict) -> SimpleNamespace:
        os.makedirs(runtime_spec['cwd'], exist_ok=True)
        os.makedirs(os.path.dirname(runtime_spec['stdout']), exist_ok=True)
        os.makedirs(os.path.dirname(runtime_spec['pid_file']), exist_ok=True)

        if runtime_spec.get('stderr') not in ('', None, 'stdout'):
            os.makedirs(os.path.dirname(runtime_spec['stderr']), exist_ok=True)

        launch_spec = {
            'argv': runtime_spec['argv'],
            'cwd': runtime_spec['cwd'],
            'stdout': runtime_spec['stdout'],
            'stderr': runtime_spec.get('stderr') or 'stdout',
            'pid_file': runtime_spec['pid_file'],
        }

        spec_fd, spec_path = tempfile.mkstemp(
            prefix='external-tool-launch-',
            suffix='.json',
            dir=os.path.dirname(runtime_spec['pid_file']),
        )

        try:
            with os.fdopen(spec_fd, 'w', encoding='utf-8') as file_obj:
                json.dump(launch_spec, file_obj, ensure_ascii=False)

            launcher_code = r'''
import json
import os
import subprocess
import sys

spec_path = sys.argv[1]
with open(spec_path, 'r', encoding='utf-8') as file_obj:
    spec = json.load(file_obj)

stdout_file = open(spec['stdout'], 'ab')
stderr_file = None
try:
    stderr_value = spec.get('stderr') or 'stdout'
    if stderr_value == 'stdout':
        stderr_target = subprocess.STDOUT
    else:
        stderr_file = open(stderr_value, 'ab')
        stderr_target = stderr_file

    kwargs = {
        'cwd': spec['cwd'],
        'stdin': subprocess.DEVNULL,
        'stdout': stdout_file,
        'stderr': stderr_target,
        'close_fds': True,
        'shell': False,
    }

    if os.name == 'nt':
        flags = 0
        flags |= getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
        flags |= getattr(subprocess, 'DETACHED_PROCESS', 0)
        process = subprocess.Popen(spec['argv'], creationflags=flags, **kwargs)
    else:
        process = subprocess.Popen(spec['argv'], start_new_session=True, **kwargs)

    with open(spec['pid_file'], 'w', encoding='utf-8') as pid_obj:
        pid_obj.write(str(process.pid))
    print(process.pid)
finally:
    stdout_file.close()
    if stderr_file is not None:
        stderr_file.close()
'''

            completed = subprocess.run(
                [sys.executable, '-c', launcher_code, spec_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                close_fds=True,
            )

            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or 'external tool launcher failed').strip())

            pid_text = (completed.stdout or '').strip().splitlines()[-1]
            return SimpleNamespace(pid=int(pid_text))

        finally:
            try:
                os.unlink(spec_path)
            except OSError:
                pass

    def _read_pid_file(self, pid_file: str) -> int | None:
        try:
            with open(pid_file, 'r', encoding='utf-8') as file_obj:
                text = file_obj.read().strip()
            pid = int(text)
            return pid if pid > 0 else None
        except Exception:
            return None

    def _is_pid_alive(self, pid: int | None) -> bool:
        if not pid or pid <= 0:
            return False

        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            return e.errno == errno.EPERM
        except Exception:
            return False

    def _signal_process_group_or_pid(self, pid: int, sig: int):
        if os.name != 'nt':
            try:
                os.killpg(pid, sig)
                return
            except ProcessLookupError:
                return
            except Exception:
                pass

        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return

    def _read_json_file(self, path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as file_obj:
            data = json.load(file_obj)
        return data if isinstance(data, dict) else {}

    def _write_json_file(self, path: str, data: dict):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=2)

    def _default_instance_runtime_dir(self, tool_id: str, instance_id: str) -> str:
        return self._safe_join_runtime(tool_id, 'instances', self._sanitize_instance_id(instance_id))

    def _state_path_for(self, tool_id: str, instance_id: str) -> str:
        return os.path.join(self._default_instance_runtime_dir(tool_id, instance_id), 'state.json')

    def _state_or_default_runtime(self, meta: dict, instance_id: str) -> dict:
        tool_id = str(meta.get('id') or '').strip()
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
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'side': state.get('side') or self._meta_primary_side(meta),
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

    def _write_state_file(
        self,
        meta: dict,
        context: dict,
        runtime_spec: dict,
        process: SimpleNamespace,
        install_info: dict,
        config_info: dict,
        params: dict,
    ) -> str:
        state_file = runtime_spec.get('state_file') or context.get('state_file') or os.path.join(os.path.dirname(runtime_spec['pid_file']), 'state.json')

        payload = {
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or '',
            'version': meta.get('version') or '',
            'side': context.get('side') or self._meta_primary_side(meta),
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
            stop = {
                'type': 'signal',
                'signal': 'TERM',
                'timeout_sec': self.DEFAULT_STOP_TIMEOUT_SEC,
                'kill_after_timeout': True,
            }

        return stop

    def _signal_name_to_value(self, value: Any) -> int:
        text = str(value or 'TERM').strip().upper()
        if not text.startswith('SIG'):
            text = 'SIG' + text
        return int(getattr(signal, text, signal.SIGTERM))

    def _run_lifecycle_command(self, stop_spec: dict, context: dict) -> dict:
        argv = stop_spec.get('argv') or stop_spec.get('command') or []
        rendered = self._render_value(argv, context)

        if isinstance(rendered, str):
            rendered = shlex.split(rendered)

        if not isinstance(rendered, list) or not rendered:
            raise ValueError('lifecycle.stop.argv is required for command stop')

        rendered = [
            self._expand_path(str(item))
            if self._should_expand_argv_item(str(item), index)
            else str(item)
            for index, item in enumerate(rendered)
        ]

        timeout = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)

        completed = subprocess.run(
            rendered,
            cwd=self._expand_path(self._render_value(stop_spec.get('cwd') or context.get('instance_runtime_dir') or '.', context)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1, timeout),
            close_fds=True,
        )

        return {
            'type': 'command',
            'argv': rendered,
            'returncode': completed.returncode,
            'stdout': completed.stdout,
            'stderr': completed.stderr,
        }

    def _stop_by_signal(self, pid: int | None, stop_spec: dict) -> dict:
        if not pid:
            return {'type': 'signal', 'signal': '', 'sent': False, 'message': 'pid not found'}

        sig = self._signal_name_to_value(stop_spec.get('signal') or 'TERM')
        timeout_sec = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)
        kill_after_timeout = bool(stop_spec.get('kill_after_timeout', True))

        self._signal_process_group_or_pid(pid, sig)

        deadline = time.time() + max(0.1, timeout_sec)
        while time.time() < deadline:
            if not self._is_pid_alive(pid):
                return {
                    'type': 'signal',
                    'signal': signal.Signals(sig).name,
                    'sent': True,
                    'killed': False,
                }
            time.sleep(0.1)

        killed = False
        if kill_after_timeout and self._is_pid_alive(pid):
            self._signal_process_group_or_pid(pid, signal.SIGKILL)
            killed = True

        return {
            'type': 'signal',
            'signal': signal.Signals(sig).name,
            'sent': True,
            'killed': killed,
        }

    def _mark_stopped(self, state_file: str, stop_result: dict):
        state = self._read_json_file(state_file) if os.path.isfile(state_file) else {}
        state = state if isinstance(state, dict) else {}
        state['last_status'] = 'stopped'
        state['stopped_at'] = datetime.now().isoformat(timespec='seconds')
        state['stop_result'] = stop_result
        self._write_json_file(state_file, state)

    def _ensure_server_instance_stopped(self, meta: dict, instance_id: str) -> dict:
        status = self._status_from_state(meta, instance_id)
        if status.get('running'):
            raise ValueError('Stop this instance before modifying runtime files.')
        return status

    def start_server_instance(
        self,
        tool_id: str,
        params: dict | None = None,
        instance_id: str = '',
        install_if_needed: bool = True,
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        resolved_params = self.resolve_params(meta, params)
        context = self.build_server_context(meta, resolved_params, instance_id=instance_id)
        instance_id = context['instance_id']

        os.makedirs(context['instance_runtime_dir'], exist_ok=True)

        if install_if_needed:
            install_info = self._install_package_if_needed(meta, context)
        else:
            install_info = self._build_install_status(meta, context)
            if not install_info.get('installed'):
                raise ValueError('Package is not installed. Please install it first.')
            install_info.update({
                'already_installed': True,
                'extracted': False,
                'message': 'using existing installation',
            })
            self._chmod_executable(install_info.get('executable_path') or '')

        config_info = self._write_config(meta, context)
        runtime_spec = self._build_runtime_spec(meta, context)

        existing_pid = self._read_pid_file(runtime_spec['pid_file'])
        if self._is_pid_alive(existing_pid):
            status = self._status_from_state(meta, instance_id)
            status['message'] = f'{meta.get("display_name") or meta.get("id")} instance {instance_id} is already running'
            return status

        process = self._start_detached_process(runtime_spec)
        state_file = self._write_state_file(meta, context, runtime_spec, process, install_info, config_info, resolved_params)

        return {
            'tool_id': meta.get('id') or '',
            'side': 'server',
            'instance_id': instance_id,
            'status': 'running',
            'running': True,
            'pid': process.pid,
            'install': install_info,
            'config': config_info,
            'runtime': runtime_spec,
            'state_file': state_file,
            'message': f'{meta.get("display_name") or meta.get("id")} instance {instance_id} started on server',
        }

    def install_server_tool(self, tool_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        resolved_params = self.resolve_params(meta, params or {}, require_required=False)
        context = self.build_server_context(meta, resolved_params, instance_id=instance_id)
        install_info = self._install_package_if_needed(meta, context)

        install_info['message'] = (
            f'{meta.get("display_name") or meta.get("id")} already installed at {install_info.get("install_dir")}'
            if install_info.get('already_installed')
            else f'{meta.get("display_name") or meta.get("id")} installed at {install_info.get("install_dir")}'
        )

        return install_info

    def server_install_status(self, tool_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        resolved_params = self.resolve_params(meta, params or {}, require_required=False)
        context = self.build_server_context(meta, resolved_params, instance_id=instance_id)
        status = self._build_install_status(meta, context)

        status['message'] = (
            f'{meta.get("display_name") or meta.get("id")} is installed at {status.get("install_dir")}'
            if status.get('installed')
            else f'{meta.get("display_name") or meta.get("id")} is not installed. Please install it first.'
        )

        return status

    def _has_running_server_instances(self, meta: dict) -> bool:
        tool_runtime = self._safe_join_runtime(meta.get('id') or '', 'instances')
        if not os.path.isdir(tool_runtime):
            return False

        for name in os.listdir(tool_runtime):
            path = os.path.join(tool_runtime, name)
            if not os.path.isdir(path):
                continue
            status = self._status_from_state(meta, name)
            if status.get('running'):
                return True

        return False

    def uninstall_server_tool(self, tool_id: str, params: dict | None = None, instance_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        if self._has_running_server_instances(meta):
            raise ValueError('This package has running instances on server. Stop them before uninstalling.')

        resolved_params = self.resolve_params(meta, params or {}, require_required=False)
        context = self.build_server_context(meta, resolved_params, instance_id=instance_id)
        status = self._build_install_status(meta, context)
        install_dir = status.get('install_dir') or ''

        removed = False
        if install_dir and os.path.isdir(install_dir):
            shutil.rmtree(install_dir)
            removed = True

        status.update({
            'installed': False,
            'removed': removed,
            'message': (
                f'{meta.get("display_name") or meta.get("id")} uninstalled from {install_dir}'
                if removed
                else f'{meta.get("display_name") or meta.get("id")} was not installed at {install_dir}'
            ),
        })

        return status

    def stop_server_instance(self, tool_id: str, instance_id: str, params: dict | None = None) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        instance_id = self._sanitize_instance_id(instance_id)
        status_before = self._status_from_state(meta, instance_id)
        pid = status_before.get('pid')
        info = self._state_or_default_runtime(meta, instance_id)
        stop_spec = self._resolve_stop_lifecycle(meta)

        context = self.build_server_context(meta, params or {}, instance_id=instance_id)
        context.update({
            'pid': pid or '',
            'pid_file': info['runtime']['pid_file'],
            'stdout': info['runtime'].get('stdout') or '',
            'state_file': info['state_file'],
        })

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
        status_after['message'] = f'{meta.get("display_name") or meta.get("id")} instance {instance_id} stop requested'

        return status_after

    def status_server_instance(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')
        return self._status_from_state(meta, self._sanitize_instance_id(instance_id))

    def list_server_instances(self, tool_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        tool_runtime = self._safe_join_runtime(meta.get('id') or '', 'instances')
        items = []

        if os.path.isdir(tool_runtime):
            for name in sorted(os.listdir(tool_runtime)):
                path = os.path.join(tool_runtime, name)
                if os.path.isdir(path):
                    items.append(self._status_from_state(meta, name))

        return {'tool_id': meta.get('id') or '', 'side': 'server', 'items': items}

    def list_all_server_instances(self, metas: list[dict]) -> dict:
        items = []
        by_tool = {}
        errors = []

        for meta in metas or []:
            tool_id = str(meta.get('id') or '').strip()
            if not tool_id:
                continue

            tool_items = []
            by_tool[tool_id] = tool_items

            try:
                self._assert_tool_usable(meta, 'server')

                tool_runtime = self._safe_join_runtime(tool_id, 'instances')

                if os.path.isdir(tool_runtime):
                    for name in sorted(os.listdir(tool_runtime)):
                        path = os.path.join(tool_runtime, name)
                        if not os.path.isdir(path):
                            continue

                        row = self._status_from_state(meta, name)
                        tool_items.append(row)
                        items.append(row)

            except Exception as e:
                errors.append({
                    'tool_id': tool_id,
                    'message': str(e),
                })

        return {
            'side': 'server',
            'items': items,
            'by_tool': by_tool,
            'errors': errors,
        }

    def list_all_client_instances(self, client_id: str, metas: list[dict], tab_id: str = '') -> dict:
        tools = []
        errors = []

        for meta in metas or []:
            tool_id = str(meta.get('id') or '').strip()
            if not tool_id:
                continue

            try:
                self._assert_tool_usable(meta, 'client', platform_alias='*')
                tools.append({
                    'tool_id': tool_id,
                    'display_name': meta.get('display_name') or meta.get('id') or tool_id,
                })
            except Exception as e:
                errors.append({
                    'tool_id': tool_id,
                    'message': str(e),
                })

        payload = {
            'action': 'list_all',
            'tools': tools,
            'errors': errors,
        }

        command = f'external_tool_list_instances_all {self._encode_payload_arg(payload)}'
        result = self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

        if isinstance(result, dict):
            result.setdefault('side', 'client')
            result.setdefault('errors', errors)
            return result

        return result



    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes: int | None = None) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        instance_id = self._sanitize_instance_id(instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        log_file = info['runtime'].get('stdout') or os.path.join(info['instance_runtime_dir'], 'stdout.log')
        max_bytes = int(max_bytes or self.DEFAULT_LOG_TAIL_BYTES)

        content = ''
        if os.path.isfile(log_file):
            with open(log_file, 'rb') as file_obj:
                if max_bytes > 0:
                    file_obj.seek(0, os.SEEK_END)
                    size = file_obj.tell()
                    file_obj.seek(max(0, size - max_bytes), os.SEEK_SET)
                raw = file_obj.read()
            content = raw.decode('utf-8', errors='replace')

        return {
            'tool_id': meta.get('id') or '',
            'instance_id': instance_id,
            'log_file': log_file,
            'content': content,
            'max_bytes': max_bytes,
        }

    def remove_server_instance(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        instance_id = self._sanitize_instance_id(instance_id)
        status = self._ensure_server_instance_stopped(meta, instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        runtime_dir = self._expand_path(info.get('instance_runtime_dir') or '')

        if runtime_dir and os.path.isdir(runtime_dir):
            shutil.rmtree(runtime_dir)

        return {
            'tool_id': meta.get('id') or '',
            'side': 'server',
            'instance_id': instance_id,
            'removed': True,
            'runtime_dir': runtime_dir,
            'previous_status': status,
            'message': f'{meta.get("display_name") or meta.get("id")} instance {instance_id} runtime removed',
        }

    def clear_server_logs(self, tool_id: str, instance_id: str) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'server')

        instance_id = self._sanitize_instance_id(instance_id)
        status = self._ensure_server_instance_stopped(meta, instance_id)
        info = self._state_or_default_runtime(meta, instance_id)
        log_file = info['runtime'].get('stdout') or os.path.join(info['instance_runtime_dir'], 'stdout.log')
        log_file = self._expand_path(log_file)

        if os.path.isfile(log_file):
            with open(log_file, 'w', encoding='utf-8'):
                pass

        return {
            'tool_id': meta.get('id') or '',
            'side': 'server',
            'instance_id': instance_id,
            'cleared': True,
            'log_file': log_file,
            'previous_status': status,
            'message': f'{meta.get("display_name") or meta.get("id")} instance {instance_id} logs cleared',
        }

    def install_and_run_server(self, tool_id: str, params: dict | None = None) -> dict:
        return self.start_server_instance(tool_id, params=params)

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def build_client_start_payload(
        self,
        meta: dict,
        params: dict | None = None,
        instance_id: str = '',
        install_if_needed: bool = True,
        require_required_params: bool = True,
    ) -> dict:
        resolved_params = self.resolve_params(meta, params, require_required=require_required_params)
        context = self.build_client_context(meta, resolved_params, instance_id=instance_id)
        rendered_meta = self._render_value(meta, context)

        package = rendered_meta.get('package') or {}
        filename = str(package.get('filename') or '').strip()
        if not filename:
            raise ValueError('package.filename is required')

        download_url = str(package.get('download_url') or '').strip()
        if not download_url:
            download_url = f'/api/external-tools/packages/{filename}'

        install = rendered_meta.get('install') or {}
        config = rendered_meta.get('config') or {}
        runtime = rendered_meta.get('runtime') or {}
        runtime.setdefault('state_file', context.get('state_file') or '')

        skip_if_exists = str(install.get('skip_if_exists') or '').strip()
        if not skip_if_exists:
            executable_rel_path = str(package.get('executable_rel_path') or '').strip()
            skip_if_exists = '{{install_dir}}/' + executable_rel_path if executable_rel_path else '{{install_dir}}'
            skip_if_exists = self._render_value(skip_if_exists, context)

        config_payload = {}
        if config.get('target') and config.get('template') is not None:
            config_payload = {
                'target': config.get('target'),
                'content': self._render_value(str(config.get('template')), context),
            }

        return {
            'action': 'start',
            'install_if_needed': bool(install_if_needed),
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'version': meta.get('version') or '',
            'side': 'client',
            'instance_id': context.get('instance_id') or 'default',
            'instance_name': context.get('instance_name') or context.get('instance_id') or 'default',
            'params': resolved_params,
            'package': {
                'filename': filename,
                'download_url': download_url,
                'executable_rel_path': package.get('executable_rel_path') or '',
            },
            'install': {
                'install_dir': context.get('install_dir') or '',
                'skip_if_exists': skip_if_exists,
            },
            'config': config_payload,
            'runtime': runtime,
            'lifecycle': rendered_meta.get('lifecycle') or {},
        }

    def build_client_payload(self, meta: dict, params: dict | None = None) -> dict:
        return self.build_client_start_payload(meta, params=params)

    def build_client_action_payload(
        self,
        meta: dict,
        action: str,
        instance_id: str = '',
        params: dict | None = None,
        max_bytes: int | None = None,
    ) -> dict:
        resolved_params = self.resolve_params(meta, params or {}, require_required=False) if params else {}
        context = self.build_client_context(meta, resolved_params, instance_id=instance_id)
        runtime_dir = context.get('instance_runtime_dir')

        runtime = {
            'pid_file': os.path.join(runtime_dir, 'tool.pid'),
            'stdout': os.path.join(runtime_dir, 'stdout.log'),
            'stderr': 'stdout',
            'state_file': os.path.join(runtime_dir, 'state.json'),
        }

        rendered_meta = self._render_value(meta, context)

        return {
            'action': action,
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'version': meta.get('version') or '',
            'side': 'client',
            'instance_id': context.get('instance_id') or 'default',
            'instance_name': context.get('instance_name') or context.get('instance_id') or 'default',
            'params': resolved_params,
            'runtime': runtime,
            'lifecycle': rendered_meta.get('lifecycle') or {},
            'max_bytes': int(max_bytes or self.DEFAULT_LOG_TAIL_BYTES),
        }

    def build_client_install_status_payloads(self, metas: list[dict]) -> list[dict]:
        payloads = []

        for meta in metas or []:
            try:
                if not self._meta_supports_side(meta, 'client'):
                    continue

                self._assert_tool_usable(meta, 'client', platform_alias='*')

                payload = self.build_client_start_payload(
                    meta,
                    params={},
                    instance_id='',
                    install_if_needed=True,
                    require_required_params=False,
                )
                payload['action'] = 'install_status'
                payloads.append(payload)

            except Exception as e:
                payloads.append({
                    'action': 'install_status',
                    'tool_id': meta.get('id') or '',
                    'display_name': meta.get('display_name') or meta.get('id') or '',
                    'side': 'client',
                    'error': str(e),
                })

        return payloads

    def _run_client_lifecycle_command(self, client_id: str, command: str, tab_id: str = '') -> dict:
        if self.remote_execution_service is None:
            return self.command_execution_api.submit_web_command(client_id, command, tab_id=tab_id)

        del tab_id
        return self.remote_execution_service.run_foreground_json_command(
            client_id,
            command,
            task_type='external_tool',
            source='web_external_tool',
        )

    def start_client_instance(
        self,
        client_id: str,
        tool_id: str,
        params: dict | None = None,
        tab_id: str = '',
        instance_id: str = '',
        install_if_needed: bool = True,
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_start_payload(
            meta,
            params=params,
            instance_id=instance_id,
            install_if_needed=install_if_needed,
        )
        command = f'external_tool_start {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def install_client_tool(
        self,
        client_id: str,
        tool_id: str,
        params: dict | None = None,
        tab_id: str = '',
        instance_id: str = '',
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_start_payload(
            meta,
            params=params,
            instance_id=instance_id,
            install_if_needed=True,
            require_required_params=False,
        )
        payload['action'] = 'install'

        command = f'external_tool_install {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def client_install_status(
        self,
        client_id: str,
        tool_id: str,
        params: dict | None = None,
        tab_id: str = '',
        instance_id: str = '',
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_start_payload(
            meta,
            params=params,
            instance_id=instance_id,
            install_if_needed=True,
            require_required_params=False,
        )
        payload['action'] = 'install_status'

        command = f'external_tool_install_status {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def uninstall_client_tool(
            self,
            client_id: str,
            tool_id: str,
            params: dict | None = None,
            tab_id: str = '',
            instance_id: str = '',
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_start_payload(
            meta,
            params=params,
            instance_id=instance_id,
            install_if_needed=True,
            require_required_params=False,
        )
        payload['action'] = 'uninstall'

        command = f'external_tool_uninstall {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)



    def client_install_statuses(self, client_id: str, metas: list[dict], tab_id: str = '') -> dict:
        payload = {
            'action': 'install_statuses',
            'tools': self.build_client_install_status_payloads(metas),
        }
        command = f'external_tool_install_statuses {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def stop_client_instance(
        self,
        client_id: str,
        tool_id: str,
        instance_id: str,
        params: dict | None = None,
        tab_id: str = '',
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_action_payload(meta, 'stop', instance_id=instance_id, params=params)
        command = f'external_tool_stop {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def status_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_action_payload(meta, 'status', instance_id=instance_id)
        command = f'external_tool_status {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def list_client_instances(self, client_id: str, tool_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = {
            'action': 'list',
            'tool_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or meta.get('id') or '',
            'side': 'client',
        }
        command = f'external_tool_list_instances {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def read_client_logs(
        self,
        client_id: str,
        tool_id: str,
        instance_id: str,
        max_bytes: int | None = None,
        tab_id: str = '',
    ) -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_action_payload(
            meta,
            'logs',
            instance_id=instance_id,
            max_bytes=max_bytes,
        )
        command = f'external_tool_logs {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def remove_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_action_payload(meta, 'remove', instance_id=instance_id)
        command = f'external_tool_remove {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def clear_client_logs(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = '') -> dict:
        meta = self.catalog_service.get_tool(tool_id)
        self._assert_tool_usable(meta, 'client', platform_alias='*')

        payload = self.build_client_action_payload(meta, 'clear_logs', instance_id=instance_id)
        command = f'external_tool_clear_logs {self._encode_payload_arg(payload)}'
        return self._run_client_lifecycle_command(client_id, command, tab_id=tab_id)

    def install_and_run_client(self, client_id: str, tool_id: str, params: dict | None = None, tab_id: str = '') -> dict:
        return self.start_client_instance(client_id, tool_id, params=params, tab_id=tab_id)