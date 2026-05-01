import errno
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import sys

from client.commands.runtime.interrupts import interruptible
from core.utils.client_util import safe_extract_zip_file
from core.utils.decorator import desc


_INSTANCE_PATTERN = re.compile(r'[^A-Za-z0-9_.-]+')


class CommandExternalToolMixin:
    """
    Client-side external tool lifecycle commands.

    Server renders the payload; client performs local operations:
    - check/install package
    - write config
    - start detached process
    - stop/status/list/logs/remove/clear logs
    """

    DOWNLOAD_TIMEOUT = (15, 600)
    DOWNLOAD_CHUNK_SIZE = 64 * 1024
    DEFAULT_STOP_TIMEOUT_SEC = 5
    DEFAULT_LOG_TAIL_BYTES = 65536

    def _external_tool_expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def _external_tool_sanitize_instance_id(self, value) -> str:
        text = str(value or '').strip()
        text = _INSTANCE_PATTERN.sub('-', text).strip('.-_')
        return (text or 'default')[:96]

    def _external_tool_render_path_list(self, values):
        if isinstance(values, str):
            return shlex.split(values)
        if isinstance(values, list):
            return [str(item) for item in values]
        return []

    def _external_tool_is_url_like(self, value: str) -> bool:
        text = str(value or '').strip().lower()
        if '://' not in text:
            return False
        scheme = text.split('://', 1)[0]
        return bool(scheme) and all(ch.isalnum() or ch in '+-.' for ch in scheme)

    def _external_tool_should_expand_argv_item(self, value: str, index: int) -> bool:
        text = str(value or '').strip()
        if not text:
            return False
        if self._external_tool_is_url_like(text):
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

    def _external_tool_chmod(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return
        mode = os.stat(path).st_mode
        os.chmod(path, mode | 0o111)

    def _external_tool_download_package(self, payload: dict) -> str:
        package = payload.get('package') or {}
        filename = os.path.basename(str(package.get('filename') or '').strip())
        download_url = str(package.get('download_url') or '').strip()

        if not filename:
            raise ValueError('package.filename is required')
        if not download_url:
            raise ValueError('package.download_url is required')

        cache_dir = self._external_tool_expand_path('~/.ops/external_tools/packages')
        os.makedirs(cache_dir, exist_ok=True)

        archive_path = os.path.join(cache_dir, filename)
        if os.path.isfile(archive_path) and os.path.getsize(archive_path) > 0:
            return archive_path

        self.client_api.download_file(
            download_url,
            archive_path,
            timeout=self.DOWNLOAD_TIMEOUT,
            chunk_size=self.DOWNLOAD_CHUNK_SIZE,
            ensure_not_interrupted=self._ensure_not_interrupted,
        )

        return archive_path

    def _external_tool_install_status_payload(self, payload: dict) -> dict:
        install = payload.get('install') or {}
        install_dir = self._external_tool_expand_path(
            install.get('install_dir') or '~/.ops/external_tools/installed/unknown'
        )
        skip_if_exists = self._external_tool_expand_path(install.get('skip_if_exists') or install_dir)

        package = payload.get('package') or {}
        executable_rel_path = str(package.get('executable_rel_path') or '').strip()
        executable_path = (
            self._external_tool_expand_path(os.path.join(install_dir, executable_rel_path))
            if executable_rel_path
            else skip_if_exists
        )
        installed = os.path.exists(skip_if_exists)

        return {
            'tool_id': payload.get('tool_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'side': payload.get('side') or 'client',
            'installed': installed,
            'install_dir': install_dir,
            'skip_path': skip_if_exists,
            'executable_path': executable_path,
            'command': shlex.quote(executable_path),
            'message': (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is installed at {install_dir}'
                if installed
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is not installed. Please install it first.'
            ),
        }

    def _external_tool_install_if_needed(self, payload: dict, archive_path: str) -> dict:
        status = self._external_tool_install_status_payload(payload)
        install_dir = status['install_dir']
        already_installed = bool(status['installed'])
        extracted = False

        if not already_installed:
            os.makedirs(install_dir, exist_ok=True)
            safe_extract_zip_file(archive_path, install_dir)
            extracted = True

        executable_path = status['executable_path']
        self._external_tool_chmod(executable_path)

        status.update({
            'installed': True,
            'already_installed': already_installed,
            'extracted': extracted,
            'message': 'already installed' if already_installed else 'installed successfully',
        })

        return status

    def _external_tool_write_config(self, payload: dict) -> dict:
        config = payload.get('config') or {}
        target = str(config.get('target') or '').strip()
        if not target:
            return {}

        content = str(config.get('content') or '')
        target_path = self._external_tool_expand_path(target)

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as file_obj:
            file_obj.write(content)

        return {'target': target_path, 'size': os.path.getsize(target_path)}

    def _external_tool_build_runtime(self, payload: dict) -> dict:
        runtime = payload.get('runtime') or {}
        argv = self._external_tool_render_path_list(runtime.get('argv') or [])

        if not argv:
            raise ValueError('runtime.argv is required')

        argv = [
            self._external_tool_expand_path(item)
            if self._external_tool_should_expand_argv_item(item, index)
            else item
            for index, item in enumerate(argv)
        ]

        cwd = self._external_tool_expand_path(runtime.get('cwd') or os.getcwd())
        stdout = self._external_tool_expand_path(runtime.get('stdout') or '~/.ops/external_tools/runtime/stdout.log')
        stderr = runtime.get('stderr') or 'stdout'

        if stderr != 'stdout':
            stderr = self._external_tool_expand_path(stderr)

        pid_file = self._external_tool_expand_path(runtime.get('pid_file') or '~/.ops/external_tools/runtime/tool.pid')
        state_file = self._external_tool_expand_path(
            runtime.get('state_file') or os.path.join(os.path.dirname(pid_file), 'state.json')
        )

        return {
            'argv': argv,
            'cwd': cwd,
            'stdout': stdout,
            'stderr': stderr,
            'pid_file': pid_file,
            'state_file': state_file,
        }

    def _external_tool_start_detached(self, runtime: dict) -> SimpleNamespace:
        os.makedirs(runtime['cwd'], exist_ok=True)
        os.makedirs(os.path.dirname(runtime['stdout']), exist_ok=True)
        os.makedirs(os.path.dirname(runtime['pid_file']), exist_ok=True)

        if runtime.get('stderr') not in ('', None, 'stdout'):
            os.makedirs(os.path.dirname(runtime['stderr']), exist_ok=True)

        launch_spec = {
            'argv': runtime['argv'],
            'cwd': runtime['cwd'],
            'stdout': runtime['stdout'],
            'stderr': runtime.get('stderr') or 'stdout',
            'pid_file': runtime['pid_file'],
        }

        spec_fd, spec_path = tempfile.mkstemp(
            prefix='external-tool-launch-',
            suffix='.json',
            dir=os.path.dirname(runtime['pid_file']),
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

    def _external_tool_read_pid(self, pid_file: str):
        try:
            with open(pid_file, 'r', encoding='utf-8') as file_obj:
                text = file_obj.read().strip()
            pid = int(text)
            return pid if pid > 0 else None
        except Exception:
            return None

    def _external_tool_is_pid_alive(self, pid) -> bool:
        if not pid or pid <= 0:
            return False

        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            return e.errno == errno.EPERM
        except Exception:
            return False

    def _external_tool_signal_process_group_or_pid(self, pid: int, sig: int):
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

    def _external_tool_read_json(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as file_obj:
                data = json.load(file_obj)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _external_tool_write_json(self, path: str, data: dict):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=2)

    def _external_tool_state_file_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        state_file = runtime.get('state_file')
        if state_file:
            return self._external_tool_expand_path(state_file)

        pid_file = self._external_tool_expand_path(runtime.get('pid_file') or '~/.ops/external_tools/runtime/tool.pid')
        return os.path.join(os.path.dirname(pid_file), 'state.json')

    def _external_tool_pid_file_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        return self._external_tool_expand_path(
            runtime.get('pid_file') or os.path.join(os.path.dirname(self._external_tool_state_file_from_payload(payload)), 'tool.pid')
        )

    def _external_tool_stdout_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        return self._external_tool_expand_path(
            runtime.get('stdout') or os.path.join(os.path.dirname(self._external_tool_state_file_from_payload(payload)), 'stdout.log')
        )

    def _external_tool_instance_runtime_dir_from_payload(self, payload: dict) -> str:
        return os.path.dirname(self._external_tool_state_file_from_payload(payload))

    def _external_tool_status_from_payload(self, payload: dict) -> dict:
        state_file = self._external_tool_state_file_from_payload(payload)
        pid_file = self._external_tool_pid_file_from_payload(payload)
        stdout = self._external_tool_stdout_from_payload(payload)
        state = self._external_tool_read_json(state_file)

        pid = self._external_tool_read_pid(pid_file)
        alive = self._external_tool_is_pid_alive(pid)

        if alive:
            status = 'running'
        elif os.path.exists(pid_file):
            status = 'stale'
        elif state:
            status = state.get('last_status') or 'stopped'
        else:
            status = 'not_started'

        runtime = state.get('runtime') if isinstance(state.get('runtime'), dict) else {}

        return {
            'tool_id': payload.get('tool_id') or state.get('tool_id') or '',
            'display_name': payload.get('display_name') or state.get('display_name') or '',
            'side': payload.get('side') or state.get('side') or 'client',
            'instance_id': payload.get('instance_id') or state.get('instance_id') or 'default',
            'status': status,
            'running': alive,
            'pid': pid,
            'pid_file': pid_file,
            'state_file': state_file,
            'stdout': stdout,
            'stderr': runtime.get('stderr') or state.get('stderr') or '',
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

    def _external_tool_write_state(
        self,
        payload: dict,
        install_info: dict,
        config_info: dict,
        runtime: dict,
        process: SimpleNamespace,
    ) -> str:
        state_file = runtime.get('state_file') or os.path.join(os.path.dirname(runtime['pid_file']), 'state.json')

        state = {
            'tool_id': payload.get('tool_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'version': payload.get('version') or '',
            'side': payload.get('side') or 'client',
            'instance_id': payload.get('instance_id') or 'default',
            'instance_name': payload.get('instance_name') or payload.get('instance_id') or 'default',
            'pid': process.pid,
            'params': payload.get('params') or {},
            'install': install_info or {},
            'config': config_info or {},
            'runtime': runtime or {},
            'argv': runtime.get('argv') or [],
            'cwd': runtime.get('cwd') or '',
            'stdout': runtime.get('stdout') or '',
            'stderr': runtime.get('stderr') or '',
            'pid_file': runtime.get('pid_file') or '',
            'state_file': state_file,
            'install_dir': install_info.get('install_dir') or '',
            'started_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'last_status': 'running',
        }

        self._external_tool_write_json(state_file, state)
        return state_file

    def _external_tool_signal_name_to_value(self, value) -> int:
        text = str(value or 'TERM').strip().upper()
        if not text.startswith('SIG'):
            text = 'SIG' + text
        return int(getattr(signal, text, signal.SIGTERM))

    def _external_tool_stop_by_signal(self, pid, stop_spec: dict) -> dict:
        if not pid:
            return {'type': 'signal', 'signal': '', 'sent': False, 'message': 'pid not found'}

        sig = self._external_tool_signal_name_to_value(stop_spec.get('signal') or 'TERM')
        timeout_sec = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)
        kill_after_timeout = bool(stop_spec.get('kill_after_timeout', True))

        self._external_tool_signal_process_group_or_pid(pid, sig)

        deadline = time.time() + max(0.1, timeout_sec)
        while time.time() < deadline:
            if not self._external_tool_is_pid_alive(pid):
                return {
                    'type': 'signal',
                    'signal': signal.Signals(sig).name,
                    'sent': True,
                    'killed': False,
                }
            time.sleep(0.1)

        killed = False
        if kill_after_timeout and self._external_tool_is_pid_alive(pid):
            self._external_tool_signal_process_group_or_pid(pid, signal.SIGKILL)
            killed = True

        return {
            'type': 'signal',
            'signal': signal.Signals(sig).name,
            'sent': True,
            'killed': killed,
        }

    def _external_tool_run_stop_command(self, stop_spec: dict) -> dict:
        argv = stop_spec.get('argv') or stop_spec.get('command') or []

        if isinstance(argv, str):
            argv = shlex.split(argv)

        if not isinstance(argv, list) or not argv:
            raise ValueError('lifecycle.stop.argv is required for command stop')

        rendered = [
            self._external_tool_expand_path(str(item))
            if self._external_tool_should_expand_argv_item(str(item), index)
            else str(item)
            for index, item in enumerate(argv)
        ]

        timeout = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)

        completed = subprocess.run(
            rendered,
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

    def _external_tool_stop_command(self, payload: dict) -> dict:
        lifecycle = payload.get('lifecycle') if isinstance(payload.get('lifecycle'), dict) else {}
        stop_spec = lifecycle.get('stop') if isinstance(lifecycle.get('stop'), dict) else {}

        if not stop_spec:
            stop_spec = {
                'type': 'signal',
                'signal': 'TERM',
                'timeout_sec': self.DEFAULT_STOP_TIMEOUT_SEC,
                'kill_after_timeout': True,
            }

        pid_file = self._external_tool_pid_file_from_payload(payload)
        pid = self._external_tool_read_pid(pid_file)

        if str(stop_spec.get('type') or 'signal').strip().lower() == 'command':
            result = self._external_tool_run_stop_command(stop_spec)
            fallback = stop_spec.get('fallback') if isinstance(stop_spec.get('fallback'), dict) else None
            if fallback and self._external_tool_is_pid_alive(pid):
                result['fallback'] = self._external_tool_stop_by_signal(pid, fallback)
        else:
            result = self._external_tool_stop_by_signal(pid, stop_spec)

        if not self._external_tool_is_pid_alive(pid):
            try:
                if os.path.exists(pid_file):
                    os.unlink(pid_file)
            except OSError:
                pass

            state_file = self._external_tool_state_file_from_payload(payload)
            state = self._external_tool_read_json(state_file)
            state['last_status'] = 'stopped'
            state['stopped_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            state['stop_result'] = result
            self._external_tool_write_json(state_file, state)

        return result

    def _external_tool_list_instances_payload(self, payload: dict) -> dict:
        tool_id = payload.get('tool_id') or ''
        runtime_root = self._external_tool_expand_path('~/.ops/external_tools/runtime')
        instances_dir = os.path.join(runtime_root, tool_id, 'instances')
        items = []

        if os.path.isdir(instances_dir):
            for name in sorted(os.listdir(instances_dir)):
                path = os.path.join(instances_dir, name)
                if not os.path.isdir(path):
                    continue

                instance_payload = {
                    'tool_id': tool_id,
                    'display_name': payload.get('display_name') or tool_id,
                    'side': 'client',
                    'instance_id': name,
                    'runtime': {
                        'pid_file': os.path.join(path, 'tool.pid'),
                        'stdout': os.path.join(path, 'stdout.log'),
                        'stderr': 'stdout',
                        'state_file': os.path.join(path, 'state.json'),
                    },
                }
                items.append(self._external_tool_status_from_payload(instance_payload))

        return {'tool_id': tool_id, 'side': 'client', 'items': items}

    def _external_tool_read_logs_payload(self, payload: dict) -> dict:
        stdout = self._external_tool_stdout_from_payload(payload)
        max_bytes = int(payload.get('max_bytes') or self.DEFAULT_LOG_TAIL_BYTES)

        content = ''
        if os.path.isfile(stdout):
            with open(stdout, 'rb') as file_obj:
                if max_bytes > 0:
                    file_obj.seek(0, os.SEEK_END)
                    size = file_obj.tell()
                    file_obj.seek(max(0, size - max_bytes), os.SEEK_SET)
                raw = file_obj.read()
            content = raw.decode('utf-8', errors='replace')

        return {
            'tool_id': payload.get('tool_id') or '',
            'instance_id': payload.get('instance_id') or 'default',
            'log_file': stdout,
            'content': content,
            'max_bytes': max_bytes,
        }

    def _external_tool_ensure_instance_stopped(self, payload: dict) -> dict:
        status = self._external_tool_status_from_payload(payload)
        if status.get('running'):
            raise ValueError('Stop this instance before modifying runtime files.')
        return status

    def _external_tool_remove_instance_payload(self, payload: dict) -> dict:
        status = self._external_tool_ensure_instance_stopped(payload)
        runtime_dir = self._external_tool_instance_runtime_dir_from_payload(payload)

        if os.path.isdir(runtime_dir):
            shutil.rmtree(runtime_dir)

        return {
            'tool_id': payload.get('tool_id') or '',
            'side': payload.get('side') or 'client',
            'instance_id': payload.get('instance_id') or 'default',
            'removed': True,
            'runtime_dir': runtime_dir,
            'previous_status': status,
            'message': f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} runtime removed on client',
        }

    def _external_tool_clear_logs_payload(self, payload: dict) -> dict:
        status = self._external_tool_ensure_instance_stopped(payload)
        stdout = self._external_tool_stdout_from_payload(payload)

        if os.path.isfile(stdout):
            with open(stdout, 'w', encoding='utf-8'):
                pass

        return {
            'tool_id': payload.get('tool_id') or '',
            'side': payload.get('side') or 'client',
            'instance_id': payload.get('instance_id') or 'default',
            'cleared': True,
            'log_file': stdout,
            'previous_status': status,
            'message': f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} logs cleared on client',
        }

    @desc('Start an external tool instance', group='runtime', suggest=False)
    @interruptible()
    def external_tool_start(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            runtime = self._external_tool_build_runtime(payload)
            existing_pid = self._external_tool_read_pid(runtime['pid_file'])

            if self._external_tool_is_pid_alive(existing_pid):
                status = self._external_tool_status_from_payload(payload)
                status['message'] = f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} is already running'
                return 1, json.dumps(status, ensure_ascii=False, indent=2)

            if payload.get('install_if_needed', True):
                archive_path = self._external_tool_download_package(payload)
                install_info = self._external_tool_install_if_needed(payload, archive_path)
            else:
                archive_path = ''
                install_info = self._external_tool_install_status_payload(payload)
                if not install_info.get('installed'):
                    raise ValueError('Package is not installed. Please install it first.')
                install_info.update({
                    'already_installed': True,
                    'extracted': False,
                    'message': 'using existing installation',
                })
                self._external_tool_chmod(install_info.get('executable_path') or '')

            config_info = self._external_tool_write_config(payload)
            process = self._external_tool_start_detached(runtime)
            state_file = self._external_tool_write_state(payload, install_info, config_info, runtime, process)

            result = {
                'tool_id': payload.get('tool_id') or '',
                'side': payload.get('side') or 'client',
                'instance_id': payload.get('instance_id') or 'default',
                'status': 'running',
                'running': True,
                'pid': process.pid,
                'package': archive_path,
                'install': install_info,
                'config': config_info,
                'runtime': runtime,
                'state_file': state_file,
                'message': f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} started on client',
            }
            return 1, json.dumps(result, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to start external tool: {e}'

    @desc('Install and run an external tool package', group='runtime', suggest=False)
    @interruptible()
    def external_tool_run(self, arg=''):
        return self.external_tool_start(arg)

    @desc('Install an external tool package without starting it', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            archive_path = self._external_tool_download_package(payload)
            install_info = self._external_tool_install_if_needed(payload, archive_path)
            install_info['package'] = archive_path
            install_info['message'] = (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} already installed at {install_info.get("install_dir")}'
                if install_info.get('already_installed')
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} installed at {install_info.get("install_dir")}'
            )

            return 1, json.dumps(install_info, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to install external tool: {e}'

    @desc('Show external tool install status', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install_status(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_install_status_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool install status: {e}'

    @desc('Show external tool install statuses in one client command', group='runtime', suggest=False)
    @interruptible()
    def external_tool_install_statuses(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)

            if isinstance(payload, list):
                tools = payload
            elif isinstance(payload, dict):
                tools = payload.get('tools') or []
            else:
                return 0, 'Invalid external tool payload'

            if not isinstance(tools, list):
                return 0, 'Invalid external tool tools payload'

            items = []
            for tool_payload in tools:
                if not isinstance(tool_payload, dict):
                    continue

                try:
                    if tool_payload.get('error'):
                        raise ValueError(str(tool_payload.get('error')))
                    items.append(self._external_tool_install_status_payload(tool_payload))
                except Exception as e:
                    items.append({
                        'tool_id': tool_payload.get('tool_id') or '',
                        'display_name': tool_payload.get('display_name') or tool_payload.get('tool_id') or '',
                        'side': tool_payload.get('side') or 'client',
                        'installed': None,
                        'install_dir': '',
                        'skip_path': '',
                        'executable_path': '',
                        'command': '',
                        'error': str(e),
                        'message': str(e),
                    })

            return 1, json.dumps({'items': items}, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool install statuses: {e}'

    @desc('Stop an external tool instance', group='runtime', suggest=False)
    @interruptible()
    def external_tool_stop(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            stop_result = self._external_tool_stop_command(payload)
            status = self._external_tool_status_from_payload(payload)
            status['stop_result'] = stop_result
            status['message'] = f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} instance {payload.get("instance_id") or "default"} stop requested on client'

            return 1, json.dumps(status, ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to stop external tool: {e}'

    @desc('Show external tool instance status', group='runtime', suggest=False)
    @interruptible()
    def external_tool_status(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_status_from_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to get external tool status: {e}'

    @desc('List external tool instances', group='runtime', suggest=False)
    @interruptible()
    def external_tool_list_instances(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_list_instances_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to list external tool instances: {e}'

    @desc('Read external tool instance logs', group='runtime', suggest=False)
    @interruptible()
    def external_tool_logs(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_read_logs_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to read external tool logs: {e}'

    @desc('Remove stopped external tool instance runtime files', group='runtime', suggest=False)
    @interruptible()
    def external_tool_remove(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_remove_instance_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to remove external tool instance: {e}'

    @desc('Clear stopped external tool instance logs', group='runtime', suggest=False)
    @interruptible()
    def external_tool_clear_logs(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_clear_logs_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to clear external tool logs: {e}'