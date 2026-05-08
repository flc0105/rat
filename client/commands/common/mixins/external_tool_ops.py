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

from client.commands.runtime.context import CommandCancelledError, CommandTimeoutError
from client.commands.runtime.interrupts import interruptible
from core.platform.platform_identity import detect_platform_alias
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

    def _external_tool_normalize_platform(self, value) -> str:
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

    def _external_tool_normalize_arch(self, value) -> str:
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

    def _external_tool_local_target(self) -> tuple[str, str]:
        local_platform = self._external_tool_normalize_platform(detect_platform_alias())
        local_arch = self._external_tool_normalize_arch(platform.machine())
        if not local_platform or not local_arch:
            raise ValueError(f'unable to detect local platform/arch, got {local_platform or "unknown"}/{local_arch or "unknown"}')
        return local_platform, local_arch

    def _external_tool_validate_package_payload(self, payload: dict, action: str = '') -> tuple[str, str]:
        requested_platform = self._external_tool_normalize_platform(payload.get('platform'))
        requested_arch = self._external_tool_normalize_arch(payload.get('arch'))
        package_key = str(payload.get('package_key') or '').strip()
        package_id = str(payload.get('package_id') or payload.get('tool_id') or '').strip()

        if not package_id:
            raise ValueError('external tool payload.package_id is required')
        if not package_key:
            raise ValueError(f'external tool payload.package_key is required for {package_id}')
        if not requested_platform or not requested_arch:
            raise ValueError(f'external tool payload platform/arch is required for {package_id}, got {requested_platform or "unknown"}/{requested_arch or "unknown"}')

        local_platform, local_arch = self._external_tool_local_target()
        platform_ok = requested_platform in ('*', local_platform)
        arch_ok = requested_arch in ('*', 'all', local_arch)
        if not platform_ok or not arch_ok:
            suffix = f' during {action}' if action else ''
            raise ValueError(
                f'external tool target mismatch{suffix}: payload requests '
                f'{requested_platform}/{requested_arch} ({package_key}) but this client is {local_platform}/{local_arch}'
            )
        return requested_platform, requested_arch

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

    def _external_tool_install_log_path(self, install_dir: str) -> str:
        return os.path.join(self._external_tool_expand_path(install_dir), '.install.log')

    def _external_tool_read_install_log(self, install_dir: str) -> str:
        path = self._external_tool_install_log_path(install_dir)
        if not os.path.isfile(path):
            return ''
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                return fh.read()
        except OSError:
            return ''

    def _external_tool_write_install_log(self, install_dir: str, lines) -> str:
        content = '\n'.join(str(line) for line in (lines or []) if str(line or '').strip())
        if not content:
            return ''
        try:
            os.makedirs(self._external_tool_expand_path(install_dir), exist_ok=True)
            with open(self._external_tool_install_log_path(install_dir), 'w', encoding='utf-8') as fh:
                fh.write(content)
                fh.write('\n')
        except OSError:
            pass
        return content

    def _external_tool_build_command_map(self, exec_paths: dict) -> dict:
        commands = {}
        for name, path in (exec_paths or {}).items():
            text = str(path or '').strip()
            if not text:
                continue
            commands[str(name)] = shlex.quote(self._external_tool_expand_path(text))
        return commands

    def _external_tool_path_has_content(self, path: str) -> bool:
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

    def _external_tool_package_cache_path(self, payload: dict) -> tuple[str, str]:
        package = payload.get('package') or {}
        filename = os.path.basename(str(package.get('filename') or '').strip())
        if not filename:
            raise ValueError('package.filename is required')
        cache_dir = self._external_tool_expand_path('~/.ops/external_tools/packages')
        return cache_dir, os.path.join(cache_dir, filename)

    def _external_tool_cache_info(self, payload: dict) -> dict:
        try:
            cache_dir, archive_path = self._external_tool_package_cache_path(payload)
        except Exception as e:
            return {
                'cache_dir': self._external_tool_expand_path('~/.ops/external_tools/packages'),
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

    def _external_tool_download_package(self, payload: dict) -> dict:
        self._external_tool_validate_package_payload(payload, 'download')
        package = payload.get('package') or {}
        download_url = str(package.get('download_url') or '').strip()

        if not download_url:
            raise ValueError('package.download_url is required')

        cache_dir, archive_path = self._external_tool_package_cache_path(payload)
        os.makedirs(cache_dir, exist_ok=True)

        before = self._external_tool_cache_info(payload)
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

        after = self._external_tool_cache_info(payload)
        after.update({
            'archive_path': archive_path,
            'source': 'download',
            'downloaded': True,
            'used_cache': False,
            'message': f'Downloaded package to cache: {archive_path}',
        })
        return after

    def _external_tool_clear_cache_payload(self, payload: dict) -> dict:
        self._external_tool_validate_package_payload(payload, 'clear-cache')
        cache = self._external_tool_cache_info(payload)
        cache_path = cache.get('cache_path') or ''
        removed = False
        if cache_path and os.path.isfile(cache_path):
            os.unlink(cache_path)
            removed = True
        after = self._external_tool_cache_info(payload)
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

    def _external_tool_install_status_payload(self, payload: dict) -> dict:
        self._external_tool_validate_package_payload(payload, 'install-status')
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
        exec_paths = {}
        raw_exec_paths = package.get('exec_paths') if isinstance(package.get('exec_paths'), dict) else {}
        for name, rel_path in raw_exec_paths.items():
            rel_text = str(rel_path or '').strip().lstrip('/\\')
            if not rel_text:
                continue
            exec_paths[str(name)] = self._external_tool_expand_path(os.path.join(install_dir, rel_text))

        # Strict FS-driven package status. This intentionally ignores old state
        # files and frontend cache: deleting install_dir must make installed False.
        install_dir_exists = os.path.isdir(install_dir)
        missing_execs = {name: path for name, path in exec_paths.items() if not os.path.isfile(path)} if install_dir_exists else dict(exec_paths)
        installed = install_dir_exists and not missing_execs

        cache = self._external_tool_cache_info(payload)
        commands = self._external_tool_build_command_map(exec_paths)

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
            'install_log': self._external_tool_read_install_log(install_dir),
            'install_log_path': self._external_tool_install_log_path(install_dir),
            'message': (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is installed at {install_dir}'
                if installed
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} is not installed. Please install it first.'
            ),
        }

    def _external_tool_install_if_needed(self, payload: dict, package_info) -> dict:
        self._external_tool_validate_package_payload(payload, 'install')
        status = self._external_tool_install_status_payload(payload)
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
        status = self._external_tool_install_status_payload(payload)
        if not status.get('installed'):
            missing = status.get('missing_execs') or {}
            install_log.append(f'Validation failed; missing execs: {missing or "-"}')
            self._external_tool_write_install_log(install_dir, install_log)
            if missing:
                raise FileNotFoundError(f'Package was extracted but configured executable paths were not found: {missing}')
            raise FileNotFoundError(f'Package was extracted but install directory was not found: {status.get("install_dir") or install_dir}')

        executable_path = status.get('executable_path') or ''
        self._external_tool_chmod(executable_path)
        for name, path in (status.get('exec_paths') or {}).items():
            self._external_tool_chmod(path)
            install_log.append(f'Validated exec {name}: {path}')

        source = package_info.get('source') or 'unknown'
        persisted_install_log = self._external_tool_write_install_log(install_dir, install_log)
        status.update({
            'installed': True,
            'already_installed': already_installed,
            'extracted': extracted,
            'package_source': source,
            'used_cache': source == 'cache',
            'downloaded': source == 'download',
            'package': archive_path,
            'cache': self._external_tool_cache_info(payload),
            'install_log': persisted_install_log,
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
        self._external_tool_validate_package_payload(payload, 'start')
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

    def _external_tool_read_pid(self, pid_file: str):
        try:
            with open(pid_file, 'r', encoding='utf-8') as file_obj:
                text = file_obj.read().strip()
            pid = int(text)
            return pid if pid > 0 else None
        except Exception:
            return None

    # def _external_tool_is_pid_alive(self, pid) -> bool:
    #     if not pid or pid <= 0:
    #         return False
    #
    #     try:
    #         os.kill(pid, 0)
    #         return True
    #     except OSError as e:
    #         return e.errno == errno.EPERM
    #     except Exception:
    #         return False

    def _external_tool_is_pid_alive(self, pid) -> bool:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False

        if pid <= 0:
            return False

        if os.name == "nt":
            return self._external_tool_is_windows_pid_alive(pid)

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

        return True

    def _external_tool_is_windows_pid_alive(self, pid: int) -> bool:
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

    # def _external_tool_signal_process_group_or_pid(self, pid: int, sig: int):
    #     if os.name != 'nt':
    #         try:
    #             os.killpg(pid, sig)
    #             return
    #         except ProcessLookupError:
    #             return
    #         except Exception:
    #             pass
    #
    #     try:
    #         os.kill(pid, sig)
    #     except ProcessLookupError:
    #         return

    def _external_tool_signal_process_group_or_pid(self, pid: int, sig: int):
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



        # If the pid file exists but the process is already gone, this is a stale
        # instance. Do not try to signal it, especially on Windows where
        # os.kill(dead_pid, sig) can raise WinError 87. Just clean runtime state.
        if not pid or not self._external_tool_is_pid_alive(pid):
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

            state_file = self._external_tool_state_file_from_payload(payload)
            state = self._external_tool_read_json(state_file)
            state['last_status'] = 'stopped'
            state['stopped_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
            state['stop_result'] = result
            self._external_tool_write_json(state_file, state)

            return result



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

    def _external_tool_runtime_parts_from_payload(self, payload: dict) -> tuple[str, str, str]:
        tool_id = str(payload.get('tool_id') or '').strip()
        package_id = str(payload.get('package_id') or '').strip()
        module_id = str(payload.get('module_id') or '').strip()
        if (not package_id or not module_id) and '.' in tool_id:
            package_id, module_id = tool_id.split('.', 1)
        if not package_id:
            package_id = tool_id
        return tool_id, package_id, module_id

    def _external_tool_list_instances_payload(self, payload: dict) -> dict:
        tool_id, package_id, module_id = self._external_tool_runtime_parts_from_payload(payload)
        runtime_root = self._external_tool_expand_path('~/.ops/external_tools/runtime')
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
                items.append(self._external_tool_status_from_payload(instance_payload))

        return {'tool_id': tool_id, 'package_id': package_id, 'module_id': module_id, 'side': 'client', 'items': items}

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

    def _external_tool_has_running_instances_for_package(self, package_id: str) -> bool:
        runtime_root = self._external_tool_expand_path('~/.ops/external_tools/runtime')
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
                status = self._external_tool_status_from_payload(instance_payload)
                if status.get('running'):
                    return True

        return False

    @desc('Uninstall an external tool package when no instances are running', group='runtime', suggest=False)
    @interruptible()
    def external_tool_uninstall(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_uninstall_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to uninstall external tool: {e}'

    def _external_tool_uninstall_payload(self, payload: dict) -> dict:
        tool_id = payload.get('tool_id') or ''
        package_id = payload.get('package_id') or tool_id
        if not package_id:
            raise ValueError('package_id is required')

        if self._external_tool_has_running_instances_for_package(package_id):
            raise ValueError('This package has running instances on this machine. Stop them before uninstalling.')

        status = self._external_tool_install_status_payload(payload)
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
                package_info = self._external_tool_download_package(payload)
                install_info = self._external_tool_install_if_needed(payload, package_info)
                archive_path = install_info.get('package') or package_info.get('archive_path') or ''
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

            package_info = self._external_tool_download_package(payload)
            install_info = self._external_tool_install_if_needed(payload, package_info)
            source_label = 'cached package' if install_info.get('used_cache') else 'downloaded package' if install_info.get('downloaded') else 'existing installation'
            install_info['message'] = (
                f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} already installed at {install_info.get("install_dir")}'
                if install_info.get('already_installed')
                else f'{payload.get("display_name") or payload.get("tool_id") or "external tool"} installed from {source_label} at {install_info.get("install_dir")}'
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

    @desc('Clear cached external tool package archive', group='runtime', suggest=False)
    @interruptible()
    def external_tool_clear_cache(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_clear_cache_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to clear external tool package cache: {e}'

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

    def _external_tool_list_instances_all_payload(self, payload: dict) -> dict:
        runtime_root = self._external_tool_expand_path('~/.ops/external_tools/runtime')
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

                row = self._external_tool_status_from_payload(instance_payload)
                tool_items.append(row)
                items.append(row)

        return {
            'side': 'client',
            'items': items,
            'by_tool': by_tool,
        }

    @desc('List all external tool instances in one command', group='runtime', suggest=False)
    @interruptible()
    def external_tool_list_instances_all(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            return 1, json.dumps(self._external_tool_list_instances_all_payload(payload), ensure_ascii=False, indent=2)

        except Exception as e:
            return 0, f'Failed to list all external tool instances: {e}'

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


    #xt
    @desc('Show installed external tool executable path', group='runtime', suggest=False)
    @interruptible()
    def external_tool_which(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid external tool payload'

            status = self._external_tool_install_status_payload(payload)
            executable_path = status.get('executable_path') or ''

            if not status.get('installed'):
                return 0, status.get('message') or 'External tool is not installed'

            if not executable_path or not os.path.exists(executable_path):
                return 0, f'External tool executable not found: {executable_path}'

            return 1, executable_path

        except Exception as e:
            return 0, f'Failed to resolve external tool executable: {e}'

    @desc('Run an installed external tool executable with raw argv', group='runtime', suggest=False)
    @interruptible()
    def external_tool_exec(self, arg=''):
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                self._send_final_result(0, 'Invalid external tool payload')
                return

            status = self._external_tool_install_status_payload(payload)
            executable_path = status.get('executable_path') or ''

            if not status.get('installed'):
                self._send_final_result(0, status.get('message') or 'External tool is not installed')
                return

            if not executable_path or not os.path.exists(executable_path):
                self._send_final_result(0, f'External tool executable not found: {executable_path}')
                return

            self._external_tool_chmod(executable_path)

            raw_args = str(payload.get('raw_args') or '').strip()
            argv_extra = payload.get('argv_extra')
            if not isinstance(argv_extra, list):
                argv_extra = shlex.split(raw_args) if raw_args else []

            argv = [executable_path] + [str(item) for item in argv_extra]

            cli = payload.get('cli') if isinstance(payload.get('cli'), dict) else {}
            cwd = self._external_tool_expand_path(cli.get('cwd') or os.getcwd())
            if not os.path.isdir(cwd):
                raise FileNotFoundError(f'external tool cli cwd does not exist: {cwd}')

            timeout_sec = cli.get('timeout_sec')
            try:
                timeout_sec = float(timeout_sec)
            except Exception:
                timeout_sec = None
            if timeout_sec is not None and timeout_sec <= 0:
                timeout_sec = None

            process = subprocess.Popen(
                argv,
                shell=False,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **self._build_process_creation_kwargs()
            )
            self._register_cancel_handler(lambda: self._terminate_process(process))

            # _start_output_threads 当前签名是 _start_output_threads(process)，超时只交给 wait 层。
            self._start_output_threads(process)
            self._wait_process_with_cancel_support(process, timeout=timeout_sec)
            time.sleep(0.1)

            if process.returncode == 0:
                self._send_final_result(1, 'Command completed')
            else:
                self._send_final_result(0, f'Command exited with code {process.returncode}')

        except CommandCancelledError:
            self._send_final_result(0, 'Command cancelled')
        except (CommandTimeoutError, subprocess.TimeoutExpired):
            self._send_final_result(0, 'Command timed out and was terminated')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute external tool: {e}')