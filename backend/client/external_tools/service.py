import errno
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import sys

from core.platform.platform_identity import detect_platform_alias
from core.utils.client_util import safe_extract_zip_file


_INSTANCE_PATTERN = re.compile(r'[^A-Za-z0-9_.-]+')


class ExternalToolClientService:
    """
    Client-side external tool lifecycle service.

    It owns package cache/install/runtime/state operations. Command mixins should
    only decode arguments, call this service, and format command results.
    """

    DOWNLOAD_TIMEOUT = (15, 600)
    DOWNLOAD_CHUNK_SIZE = 64 * 1024
    DEFAULT_STOP_TIMEOUT_SEC = 5
    DEFAULT_LOG_TAIL_BYTES = 65536

    def __init__(self, command_host):
        self.command_host = command_host

    @property
    def client_api(self):
        return self.command_host.client_api

    def _ensure_not_interrupted(self):
        return self.command_host._ensure_not_interrupted()


    def normalize_platform(self, value) -> str:
        text = str(value or '').strip().lower()
        aliases = {
            'windows': 'win',
            'win32': 'win',
            'darwin': 'mac',
            'macos': 'mac',
            'osx': 'mac',
            'linux': 'linux',
            'ios': 'ios',
            'common': '*',
            'all': '*',
            '*': '*',
        }
        return aliases.get(text, text)

    def normalize_arch(self, value) -> str:
        text = str(value or '').strip().lower().replace('-', '_')
        aliases = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'i386': '386',
            'i686': '386',
            'aarch64': 'arm64',
            'arm64': 'arm64',
        }
        return aliases.get(text, text)

    def local_target(self) -> tuple[str, str]:
        local_platform = self.normalize_platform(detect_platform_alias())
        local_arch = self.normalize_arch(platform.machine())
        if not local_platform or not local_arch:
            raise ValueError(f'unable to detect local platform/arch, got {local_platform or "unknown"}/{local_arch or "unknown"}')
        return local_platform, local_arch

    def validate_package_payload(self, payload: dict, action: str = '') -> tuple[str, str]:
        requested_platform = self.normalize_platform(payload.get('platform'))
        requested_arch = self.normalize_arch(payload.get('arch'))
        package_key = str(payload.get('package_key') or '').strip()
        package_id = str(payload.get('package_id') or payload.get('tool_id') or '').strip()

        if not package_id:
            raise ValueError('external tool payload.package_id is required')
        if not package_key:
            raise ValueError(f'external tool payload.package_key is required for {package_id}')
        if not requested_platform or not requested_arch:
            raise ValueError(f'external tool payload platform/arch is required for {package_id}, got {requested_platform or "unknown"}/{requested_arch or "unknown"}')

        local_platform, local_arch = self.local_target()
        platform_ok = requested_platform in ('*', local_platform)
        arch_ok = requested_arch in ('*', 'all', local_arch)
        if not platform_ok or not arch_ok:
            suffix = f' during {action}' if action else ''
            raise ValueError(
                f'external tool target mismatch{suffix}: payload requests '
                f'{requested_platform}/{requested_arch} ({package_key}) but this client is {local_platform}/{local_arch}'
            )
        return requested_platform, requested_arch

    def expand_path(self, path: str) -> str:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or '').strip())))

    def sanitize_instance_id(self, value) -> str:
        text = str(value or '').strip()
        text = _INSTANCE_PATTERN.sub('-', text).strip('.-_')
        return (text or 'default')[:96]

    def render_path_list(self, values):
        if isinstance(values, str):
            return shlex.split(values)
        if isinstance(values, list):
            return [str(item) for item in values]
        return []

    def is_url_like(self, value: str) -> bool:
        text = str(value or '').strip().lower()
        if '://' not in text:
            return False
        scheme = text.split('://', 1)[0]
        return bool(scheme) and all(ch.isalnum() or ch in '+-.' for ch in scheme)

    def should_expand_argv_item(self, value: str, index: int) -> bool:
        text = str(value or '').strip()
        if not text:
            return False
        if self.is_url_like(text):
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

    def chmod(self, path: str):
        if not path or os.name == 'nt' or not os.path.exists(path):
            return
        mode = os.stat(path).st_mode
        os.chmod(path, mode | 0o111)

    def install_log_path(self, install_dir: str) -> str:
        return os.path.join(self.expand_path(install_dir), '.install.log')

    def read_install_log(self, install_dir: str) -> str:
        path = self.install_log_path(install_dir)
        if not os.path.isfile(path):
            return ''
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                return fh.read()
        except OSError:
            return ''

    def write_install_log(self, install_dir: str, lines) -> str:
        content = '\n'.join(str(line) for line in (lines or []) if str(line or '').strip())
        if not content:
            return ''
        try:
            os.makedirs(self.expand_path(install_dir), exist_ok=True)
            with open(self.install_log_path(install_dir), 'w', encoding='utf-8') as fh:
                fh.write(content)
                fh.write('\n')
        except OSError:
            pass
        return content

    def build_command_map(self, exec_paths: dict) -> dict:
        commands = {}
        for name, path in (exec_paths or {}).items():
            text = str(path or '').strip()
            if not text:
                continue
            commands[str(name)] = shlex.quote(self.expand_path(text))
        return commands

    def path_has_content(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        if os.path.isfile(path):
            return True
        if os.path.isdir(path):
            try:
                return any(os.scandir(path))
            except OSError:
                return False
        return True

    def package_cache_path(self, payload: dict) -> tuple[str, str]:
        package = payload.get('package') or {}
        filename = os.path.basename(str(package.get('filename') or '').strip())
        if not filename:
            raise ValueError('package.filename is required')
        cache_dir = self.expand_path('~/.ops/external_tools/packages')
        return cache_dir, os.path.join(cache_dir, filename)

    def cache_info(self, payload: dict) -> dict:
        try:
            cache_dir, archive_path = self.package_cache_path(payload)
        except Exception as e:
            return {
                'cache_dir': self.expand_path('~/.ops/external_tools/packages'),
                'cache_path': '',
                'cached': False,
                'exists': False,
                'size': 0,
                'mtime': '',
                'error': str(e),
            }

        exists = os.path.isfile(archive_path) and os.path.getsize(archive_path) > 0
        info = {
            'cache_dir': cache_dir,
            'cache_path': archive_path,
            'cached': bool(exists),
            'exists': bool(exists),
            'size': 0,
            'mtime': '',
        }
        if exists:
            try:
                stat = os.stat(archive_path)
                info['size'] = int(stat.st_size)
                info['mtime'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
            except OSError as e:
                info['error'] = str(e)
        return info

    def download_package(self, payload: dict) -> dict:
        self.validate_package_payload(payload, 'download')
        package = payload.get('package') or {}
        download_url = str(package.get('download_url') or '').strip()

        if not download_url:
            raise ValueError('package.download_url is required')

        cache_dir, archive_path = self.package_cache_path(payload)
        os.makedirs(cache_dir, exist_ok=True)

        before = self.cache_info(payload)
        if before.get('cached'):
            before.update({
                'archive_path': archive_path,
                'source': 'cache',
                'downloaded': False,
                'used_cache': True,
                'message': f'Using cached package: {archive_path}',
            })
            return before

        self.client_api.download_file(
            download_url,
            archive_path,
            timeout=self.DOWNLOAD_TIMEOUT,
            chunk_size=self.DOWNLOAD_CHUNK_SIZE,
            ensure_not_interrupted=self._ensure_not_interrupted,
        )

        after = self.cache_info(payload)
        after.update({
            'archive_path': archive_path,
            'source': 'download',
            'downloaded': True,
            'used_cache': False,
            'message': f'Downloaded package to cache: {archive_path}',
        })
        return after

    def clear_cache_payload(self, payload: dict) -> dict:
        self.validate_package_payload(payload, 'clear-cache')
        cache = self.cache_info(payload)
        cache_path = cache.get('cache_path') or ''
        removed = False
        if cache_path and os.path.isfile(cache_path):
            os.unlink(cache_path)
            removed = True
        after = self.cache_info(payload)
        return {
            'tool_id': payload.get('tool_id') or '',
            'package_id': payload.get('package_id') or payload.get('tool_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'source': payload.get('source') or '',
            'side': payload.get('side') or 'client',
            'platform': payload.get('platform') or '',
            'arch': payload.get('arch') or '',
            'package_key': payload.get('package_key') or '',
            'cache': after,
            'cache_before': cache,
            'cache_removed': removed,
            'removed': removed,
            'message': (
                f'Removed cached package: {cache_path}'
                if removed
                else f'No cached package found: {cache_path or "-"}'
            ),
        }

    def install_status_payload(self, payload: dict) -> dict:
        self.validate_package_payload(payload, 'install-status')
        install = payload.get('install') or {}
        install_dir = self.expand_path(
            install.get('install_dir') or '~/.ops/external_tools/installed/unknown'
        )
        skip_if_exists = self.expand_path(install.get('skip_if_exists') or install_dir)

        package = payload.get('package') or {}
        executable_rel_path = str(package.get('executable_rel_path') or '').strip()
        executable_path = (
            self.expand_path(os.path.join(install_dir, executable_rel_path))
            if executable_rel_path
            else skip_if_exists
        )
        exec_paths = {}
        raw_exec_paths = package.get('exec_paths') if isinstance(package.get('exec_paths'), dict) else {}
        for name, rel_path in raw_exec_paths.items():
            rel_text = str(rel_path or '').strip().lstrip('/\\')
            if not rel_text:
                continue
            exec_paths[str(name)] = self.expand_path(os.path.join(install_dir, rel_text))

        # Strict FS-driven package status. This intentionally ignores old state
        # files and frontend cache: deleting install_dir must make installed False.
        install_dir_exists = os.path.isdir(install_dir)
        missing_execs = {name: path for name, path in exec_paths.items() if not os.path.isfile(path)} if install_dir_exists else dict(exec_paths)
        installed = install_dir_exists and not missing_execs

        cache = self.cache_info(payload)
        commands = self.build_command_map(exec_paths)

        return {
            'tool_id': payload.get('tool_id') or '',
            'package_id': payload.get('package_id') or payload.get('tool_id') or '',
            'module_id': payload.get('module_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'source': payload.get('source') or '',
            'side': payload.get('side') or 'client',
            'platform': payload.get('platform') or '',
            'arch': payload.get('arch') or '',
            'package_key': payload.get('package_key') or '',
            'installed': installed,
            'install_dir': install_dir,
            'install_dir_exists': install_dir_exists,
            'skip_path': skip_if_exists,
            'executable_path': executable_path,
            'exec_paths': exec_paths,
            'missing_execs': missing_execs,
            'cache': cache,
            'cached': bool(cache.get('cached')),
            'cache_path': cache.get('cache_path') or '',
            'command': shlex.quote(executable_path),
            'commands': commands,
            'install_log': self.read_install_log(install_dir),
            'install_log_path': self.install_log_path(install_dir),
            'message': (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is installed at {install_dir}'
                if installed
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is not installed. Please install it first.'
            ),
        }

    def install_if_needed(self, payload: dict, package_info) -> dict:
        self.validate_package_payload(payload, 'install')
        status = self.install_status_payload(payload)
        install_dir = status['install_dir']
        already_installed = bool(status['installed'])
        extracted = False
        package_info = package_info if isinstance(package_info, dict) else {'archive_path': str(package_info or ''), 'source': 'unknown'}
        archive_path = package_info.get('archive_path') or package_info.get('cache_path') or ''
        install_log = [
            f'Package: {payload.get("display_name") or payload.get("package_id") or payload.get("tool_id") or "external tool"}',
            f'Target: {payload.get("side") or "client"} {payload.get("platform") or ""} {payload.get("arch") or ""}'.rstrip(),
            f'Platform package key: {payload.get("package_key") or "-"}',
            f'Install dir: {install_dir}',
            f'Package source: {package_info.get("source") or "unknown"}',
            f'Package cache: {archive_path or "-"}',
        ]

        if not already_installed:
            if not archive_path:
                raise ValueError('package archive path is required')
            os.makedirs(install_dir, exist_ok=True)
            install_log.append(f'Extracting package to: {install_dir}')
            safe_extract_zip_file(archive_path, install_dir)
            extracted = True
        else:
            install_log.append('Existing installation is valid; extraction skipped.')

        # Re-read after extraction. Do not report success if the configured marker
        # still does not exist; otherwise the UI will flip back to not installed on
        # the next refresh.
        status = self.install_status_payload(payload)
        if not status.get('installed'):
            missing = status.get('missing_execs') or {}
            install_log.append(f'Validation failed; missing execs: {missing or "-"}')
            self.write_install_log(install_dir, install_log)
            if missing:
                raise FileNotFoundError(f'Package was extracted but configured executable paths were not found: {missing}')
            raise FileNotFoundError(f'Package was extracted but install directory was not found: {status.get("install_dir") or install_dir}')

        executable_path = status.get('executable_path') or ''
        self.chmod(executable_path)
        for name, path in (status.get('exec_paths') or {}).items():
            self.chmod(path)
            install_log.append(f'Validated exec {name}: {path}')

        source = package_info.get('source') or 'unknown'
        persisted_install_log = self.write_install_log(install_dir, install_log)
        status.update({
            'installed': True,
            'already_installed': already_installed,
            'extracted': extracted,
            'package_source': source,
            'used_cache': source == 'cache',
            'downloaded': source == 'download',
            'package': archive_path,
            'cache': self.cache_info(payload),
            'install_log': persisted_install_log,
            'message': 'already installed' if already_installed else 'installed successfully',
        })

        return status

    def write_config(self, payload: dict) -> dict:
        config = payload.get('config') or {}
        target = str(config.get('target') or '').strip()
        if not target:
            return {}

        content = str(config.get('content') or '')
        target_path = self.expand_path(target)

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as file_obj:
            file_obj.write(content)

        return {'target': target_path, 'size': os.path.getsize(target_path)}

    def build_runtime(self, payload: dict) -> dict:
        self.validate_package_payload(payload, 'start')
        runtime = payload.get('runtime') or {}
        argv = self.render_path_list(runtime.get('argv') or [])

        if not argv:
            raise ValueError('runtime.argv is required')

        argv = [
            self.expand_path(item)
            if self.should_expand_argv_item(item, index)
            else item
            for index, item in enumerate(argv)
        ]

        cwd = self.expand_path(runtime.get('cwd') or os.getcwd())
        stdout = self.expand_path(runtime.get('stdout') or '~/.ops/external_tools/runtime/stdout.log')
        stderr = runtime.get('stderr') or 'stdout'

        if stderr != 'stdout':
            stderr = self.expand_path(stderr)

        pid_file = self.expand_path(runtime.get('pid_file') or '~/.ops/external_tools/runtime/tool.pid')
        state_file = self.expand_path(
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

    def run_foreground(self, runtime: dict, timeout_sec=None) -> dict:
        cwd = self.expand_path(runtime.get('cwd') or os.getcwd())
        if not os.path.isdir(cwd):
            raise FileNotFoundError(f'external tool cwd does not exist: {cwd}')

        argv = self.render_path_list(runtime.get('argv') or [])
        if not argv:
            raise ValueError('runtime.argv is required')
        argv = [
            self.expand_path(item)
            if self.should_expand_argv_item(item, index)
            else item
            for index, item in enumerate(argv)
        ]
        self.chmod(argv[0])

        try:
            timeout_value = None if timeout_sec in ('', None) else float(timeout_sec)
        except Exception:
            raise ValueError(f'invalid oneshot timeout_sec: {timeout_sec}')
        if timeout_value is not None and timeout_value <= 0:
            raise ValueError(f'invalid oneshot timeout_sec: {timeout_sec}')

        started = time.time()
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_value,
                shell=False,
            )
            timed_out = False
            returncode = int(completed.returncode)
            stdout = completed.stdout or ''
            stderr = completed.stderr or ''
        except subprocess.TimeoutExpired as e:
            timed_out = True
            returncode = -1
            stdout = e.stdout or ''
            stderr = e.stderr or ''
            if isinstance(stdout, bytes):
                stdout = stdout.decode('utf-8', errors='replace')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8', errors='replace')
            stderr = (stderr + ('\n' if stderr else '') + f'Command timed out after {timeout_value} seconds').strip()

        finished = time.time()
        return {
            'argv': argv,
            'cwd': cwd,
            'returncode': returncode,
            'stdout': stdout,
            'stderr': stderr,
            'timed_out': timed_out,
            'started_at': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(started)),
            'finished_at': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(finished)),
            'duration_sec': round(finished - started, 3),
        }

    def start_detached(self, runtime: dict) -> SimpleNamespace:
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
import platform
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

    def read_pid(self, pid_file: str):
        try:
            with open(pid_file, 'r', encoding='utf-8') as file_obj:
                text = file_obj.read().strip()
            pid = int(text)
            return pid if pid > 0 else None
        except Exception:
            return None

    def is_pid_alive(self, pid) -> bool:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False

        if pid <= 0:
            return False

        if os.name == "nt":
            return self.is_windows_pid_alive(pid)

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

        return True

    def is_windows_pid_alive(self, pid: int) -> bool:
        """
        Windows 下不能用 os.kill(pid, 0) 探活。
        Python on Windows 的 os.kill 可能会调用 TerminateProcess，导致探测直接杀死目标进程。
        这里用 Win32 OpenProcess + GetExitCodeProcess 非破坏性检测。
        """
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5
        ERROR_INVALID_PARAMETER = 87

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype = wintypes.HANDLE

        GetExitCodeProcess = kernel32.GetExitCodeProcess
        GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        GetExitCodeProcess.restype = wintypes.BOOL

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype = wintypes.BOOL

        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = ctypes.get_last_error()

            # 没权限通常说明进程存在，只是不能查询。
            if err == ERROR_ACCESS_DENIED:
                return True

            # PID 不存在 / 参数无效。
            if err == ERROR_INVALID_PARAMETER:
                return False

            return False

        try:
            exit_code = wintypes.DWORD()
            ok = GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not ok:
                err = ctypes.get_last_error()
                if err == ERROR_ACCESS_DENIED:
                    return True
                return False

            return exit_code.value == STILL_ACTIVE
        finally:
            CloseHandle(handle)

    def signal_process_group_or_pid(self, pid: int, sig: int):
        if not pid or pid <= 0:
            return

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
        except OSError as exc:
            # Windows stale instance:
            # os.kill(dead_pid, sig) may raise [WinError 87] The parameter is incorrect.
            # Treat it as "already gone" instead of failing stop/cleanup.
            if os.name == 'nt' and getattr(exc, 'winerror', None) == 87:
                return
            if getattr(exc, 'errno', None) in (errno.ESRCH, errno.EINVAL):
                return
            raise

    def read_json(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as file_obj:
                data = json.load(file_obj)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def write_json(self, path: str, data: dict):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as file_obj:
            json.dump(data, file_obj, ensure_ascii=False, indent=2)

    def state_file_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        state_file = runtime.get('state_file')
        if state_file:
            return self.expand_path(state_file)

        pid_file = self.expand_path(runtime.get('pid_file') or '~/.ops/external_tools/runtime/tool.pid')
        return os.path.join(os.path.dirname(pid_file), 'state.json')

    def pid_file_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        return self.expand_path(
            runtime.get('pid_file') or os.path.join(os.path.dirname(self.state_file_from_payload(payload)), 'tool.pid')
        )

    def stdout_from_payload(self, payload: dict) -> str:
        runtime = payload.get('runtime') or {}
        return self.expand_path(
            runtime.get('stdout') or os.path.join(os.path.dirname(self.state_file_from_payload(payload)), 'stdout.log')
        )

    def instance_runtime_dir_from_payload(self, payload: dict) -> str:
        return os.path.dirname(self.state_file_from_payload(payload))

    def status_from_payload(self, payload: dict) -> dict:
        state_file = self.state_file_from_payload(payload)
        pid_file = self.pid_file_from_payload(payload)
        stdout = self.stdout_from_payload(payload)
        state = self.read_json(state_file)

        pid = self.read_pid(pid_file)
        alive = self.is_pid_alive(pid)

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
            'package_id': payload.get('package_id') or state.get('package_id') or '',
            'module_id': payload.get('module_id') or state.get('module_id') or '',
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

    def write_state(
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
            'package_id': payload.get('package_id') or '',
            'module_id': payload.get('module_id') or '',
            'display_name': payload.get('display_name') or payload.get('tool_id') or '',
            'version': payload.get('version') or '',
            'platform': payload.get('platform') or '',
            'arch': payload.get('arch') or '',
            'package_key': payload.get('package_key') or '',
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

        self.write_json(state_file, state)
        return state_file

    def signal_name_to_value(self, value) -> int:
        text = str(value or 'TERM').strip().upper()
        if not text.startswith('SIG'):
            text = 'SIG' + text
        return int(getattr(signal, text, signal.SIGTERM))

    def stop_by_signal(self, pid, stop_spec: dict) -> dict:
        if not pid:
            return {'type': 'signal', 'signal': '', 'sent': False, 'message': 'pid not found'}

        sig = self.signal_name_to_value(stop_spec.get('signal') or 'TERM')
        timeout_sec = int(stop_spec.get('timeout_sec') or self.DEFAULT_STOP_TIMEOUT_SEC)
        kill_after_timeout = bool(stop_spec.get('kill_after_timeout', True))

        self.signal_process_group_or_pid(pid, sig)

        deadline = time.time() + max(0.1, timeout_sec)
        while time.time() < deadline:
            if not self.is_pid_alive(pid):
                return {
                    'type': 'signal',
                    'signal': signal.Signals(sig).name,
                    'sent': True,
                    'killed': False,
                }
            time.sleep(0.1)

        killed = False
        if kill_after_timeout and self.is_pid_alive(pid):
            self.signal_process_group_or_pid(pid, signal.SIGKILL)
            killed = True

        return {
            'type': 'signal',
            'signal': signal.Signals(sig).name,
            'sent': True,
            'killed': killed,
        }

    def run_stop_command(self, stop_spec: dict) -> dict:
        argv = stop_spec.get('argv') or stop_spec.get('command') or []

        if isinstance(argv, str):
            argv = shlex.split(argv)

        if not isinstance(argv, list) or not argv:
            raise ValueError('lifecycle.stop.argv is required for command stop')

        rendered = [
            self.expand_path(str(item))
            if self.should_expand_argv_item(str(item), index)
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

    def stop_command(self, payload: dict) -> dict:
        lifecycle = payload.get('lifecycle') if isinstance(payload.get('lifecycle'), dict) else {}
        stop_spec = lifecycle.get('stop') if isinstance(lifecycle.get('stop'), dict) else {}

        if not stop_spec:
            stop_spec = {
                'type': 'signal',
                'signal': 'TERM',
                'timeout_sec': self.DEFAULT_STOP_TIMEOUT_SEC,
                'kill_after_timeout': True,
            }

        pid_file = self.pid_file_from_payload(payload)
        pid = self.read_pid(pid_file)



        # If the pid file exists but the process is already gone, this is a stale
        # instance. Do not try to signal it, especially on Windows where
        # os.kill(dead_pid, sig) can raise WinError 87. Just clean runtime state.
        if not pid or not self.is_pid_alive(pid):
            result = {
                'type': 'cleanup',
                'sent': False,
                'already_stopped': True,
                'message': 'process is not running; cleaned stale instance',
            }

            try:
                if os.path.exists(pid_file):
                    os.unlink(pid_file)
            except OSError:
                pass

            state_file = self.state_file_from_payload(payload)
            state = self.read_json(state_file)
            state['last_status'] = 'stopped'
            state['stopped_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            state['stop_result'] = result
            self.write_json(state_file, state)

            return result



        if str(stop_spec.get('type') or 'signal').strip().lower() == 'command':
            result = self.run_stop_command(stop_spec)
            fallback = stop_spec.get('fallback') if isinstance(stop_spec.get('fallback'), dict) else None
            if fallback and self.is_pid_alive(pid):
                result['fallback'] = self.stop_by_signal(pid, fallback)
        else:
            result = self.stop_by_signal(pid, stop_spec)

        if not self.is_pid_alive(pid):
            try:
                if os.path.exists(pid_file):
                    os.unlink(pid_file)
            except OSError:
                pass

            state_file = self.state_file_from_payload(payload)
            state = self.read_json(state_file)
            state['last_status'] = 'stopped'
            state['stopped_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            state['stop_result'] = result
            self.write_json(state_file, state)

        return result

    def runtime_parts_from_payload(self, payload: dict) -> tuple[str, str, str]:
        tool_id = str(payload.get('tool_id') or '').strip()
        package_id = str(payload.get('package_id') or '').strip()
        module_id = str(payload.get('module_id') or '').strip()
        if (not package_id or not module_id) and '.' in tool_id:
            package_id, module_id = tool_id.split('.', 1)
        if not package_id:
            package_id = tool_id
        return tool_id, package_id, module_id

    def list_instances_payload(self, payload: dict) -> dict:
        tool_id, package_id, module_id = self.runtime_parts_from_payload(payload)
        runtime_root = self.expand_path('~/.ops/external_tools/runtime')
        instances_dir = os.path.join(runtime_root, package_id, module_id, 'instances') if module_id else os.path.join(runtime_root, package_id, 'instances')
        items = []

        if os.path.isdir(instances_dir):
            for name in sorted(os.listdir(instances_dir)):
                path = os.path.join(instances_dir, name)
                if not os.path.isdir(path):
                    continue

                instance_payload = {
                    'tool_id': tool_id,
                    'package_id': package_id,
                    'module_id': module_id,
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
                items.append(self.status_from_payload(instance_payload))

        return {'tool_id': tool_id, 'package_id': package_id, 'module_id': module_id, 'side': 'client', 'items': items}

    def read_logs_payload(self, payload: dict) -> dict:
        stdout = self.stdout_from_payload(payload)
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

    def ensure_instance_stopped(self, payload: dict) -> dict:
        status = self.status_from_payload(payload)
        if status.get('running'):
            raise ValueError('Stop this instance before modifying runtime files.')
        return status

    def remove_instance_payload(self, payload: dict) -> dict:
        status = self.ensure_instance_stopped(payload)
        runtime_dir = self.instance_runtime_dir_from_payload(payload)

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

    def clear_logs_payload(self, payload: dict) -> dict:
        status = self.ensure_instance_stopped(payload)
        stdout = self.stdout_from_payload(payload)

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

    def has_running_instances_for_package(self, package_id: str) -> bool:
        runtime_root = self.expand_path('~/.ops/external_tools/runtime')
        package_dir = os.path.join(runtime_root, str(package_id or '').strip())

        if not os.path.isdir(package_dir):
            return False

        for module_id in os.listdir(package_dir):
            instances_dir = os.path.join(package_dir, module_id, 'instances')
            if not os.path.isdir(instances_dir):
                continue
            tool_id = f'{package_id}.{module_id}'
            for name in os.listdir(instances_dir):
                path = os.path.join(instances_dir, name)
                if not os.path.isdir(path):
                    continue
                instance_payload = {
                    'tool_id': tool_id,
                    'package_id': package_id,
                    'module_id': module_id,
                    'display_name': tool_id,
                    'side': 'client',
                    'instance_id': name,
                    'runtime': {
                        'pid_file': os.path.join(path, 'tool.pid'),
                        'stdout': os.path.join(path, 'stdout.log'),
                        'stderr': 'stdout',
                        'state_file': os.path.join(path, 'state.json'),
                    },
                }
                status = self.status_from_payload(instance_payload)
                if status.get('running'):
                    return True

        return False

    def uninstall_payload(self, payload: dict) -> dict:
        tool_id = payload.get('tool_id') or ''
        package_id = payload.get('package_id') or tool_id
        if not package_id:
            raise ValueError('package_id is required')

        if self.has_running_instances_for_package(package_id):
            raise ValueError('This package has running instances on this machine. Stop them before uninstalling.')

        status = self.install_status_payload(payload)
        install_dir = status.get('install_dir') or ''

        removed = False
        if install_dir and os.path.isdir(install_dir):
            shutil.rmtree(install_dir)
            removed = True

        status.update({
            'installed': False,
            'removed': removed,
            'message': (
                f'{payload.get("display_name") or tool_id} uninstalled from {install_dir}'
                if removed
                else f'{payload.get("display_name") or tool_id} was not installed at {install_dir}'
            ),
        })

        return status

    def list_instances_all_payload(self, payload: dict) -> dict:
        runtime_root = self.expand_path('~/.ops/external_tools/runtime')
        tools = payload.get('tools') or []

        tool_specs = []
        if isinstance(tools, list) and tools:
            for item in tools:
                if not isinstance(item, dict):
                    continue
                tool_id = str(item.get('tool_id') or item.get('id') or '').strip()
                if not tool_id:
                    continue
                tool_specs.append({
                    'tool_id': tool_id,
                    'package_id': item.get('package_id') or (tool_id.split('.', 1)[0] if '.' in tool_id else tool_id),
                    'module_id': item.get('module_id') or (tool_id.split('.', 1)[1] if '.' in tool_id else ''),
                    'display_name': item.get('display_name') or tool_id,
                })
        elif os.path.isdir(runtime_root):
            for name in sorted(os.listdir(runtime_root)):
                path = os.path.join(runtime_root, name)
                if os.path.isdir(path):
                    tool_specs.append({
                        'tool_id': name,
                        'display_name': name,
                    })

        items = []
        by_tool = {}

        for spec in tool_specs:
            tool_id = spec['tool_id']
            display_name = spec.get('display_name') or tool_id
            package_id = spec.get('package_id') or (tool_id.split('.', 1)[0] if '.' in tool_id else tool_id)
            module_id = spec.get('module_id') or (tool_id.split('.', 1)[1] if '.' in tool_id else '')
            instances_dir = os.path.join(runtime_root, package_id, module_id, 'instances') if module_id else os.path.join(runtime_root, package_id, 'instances')
            tool_items = []
            by_tool[tool_id] = tool_items

            if not os.path.isdir(instances_dir):
                continue

            for name in sorted(os.listdir(instances_dir)):
                path = os.path.join(instances_dir, name)
                if not os.path.isdir(path):
                    continue

                instance_payload = {
                    'tool_id': tool_id,
                    'package_id': package_id,
                    'module_id': module_id,
                    'display_name': display_name,
                    'side': 'client',
                    'instance_id': name,
                    'runtime': {
                        'pid_file': os.path.join(path, 'tool.pid'),
                        'stdout': os.path.join(path, 'stdout.log'),
                        'stderr': 'stdout',
                        'state_file': os.path.join(path, 'state.json'),
                    },
                }

                row = self.status_from_payload(instance_payload)
                tool_items.append(row)
                items.append(row)

        return {
            'side': 'client',
            'items': items,
            'by_tool': by_tool,
        }

