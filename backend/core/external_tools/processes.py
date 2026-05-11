import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from core.external_tools.files import write_json_file


def run_foreground_process(runtime_spec: dict, timeout_sec: float | None = None) -> dict:
    cwd = str((runtime_spec or {}).get('cwd') or '')
    if not os.path.isdir(cwd):
        raise FileNotFoundError(f'Configured runtime cwd not found: {cwd}')
    stdout_dir = os.path.dirname(str((runtime_spec or {}).get('stdout') or ''))
    if stdout_dir:
        os.makedirs(stdout_dir, exist_ok=True)

    started = time.time()
    try:
        completed = subprocess.run(
            runtime_spec.get('argv') or [],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            close_fds=True,
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
        stderr = (stderr + ('\n' if stderr else '') + f'Command timed out after {timeout_sec} seconds').strip()

    finished = time.time()
    return {
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr,
        'timed_out': timed_out,
        'started_at': datetime.fromtimestamp(started).isoformat(timespec='seconds'),
        'finished_at': datetime.fromtimestamp(finished).isoformat(timespec='seconds'),
        'duration_sec': round(finished - started, 3),
    }


def start_detached_process(runtime_spec: dict) -> SimpleNamespace:
    cwd = str((runtime_spec or {}).get('cwd') or '')
    if not os.path.isdir(cwd):
        raise FileNotFoundError(f'Configured runtime cwd not found: {cwd}')
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
    spec_fd, spec_path = tempfile.mkstemp(prefix='external-tool-launch-', suffix='.json', dir=os.path.dirname(runtime_spec['pid_file']))
    try:
        with os.fdopen(spec_fd, 'w', encoding='utf-8') as file_obj:
            import json
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
        completed = subprocess.run([sys.executable, '-c', launcher_code, spec_path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10, close_fds=True)
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or 'external tool launcher failed').strip())
        pid_text = (completed.stdout or '').strip().splitlines()[-1]
        return SimpleNamespace(pid=int(pid_text))
    finally:
        try:
            os.unlink(spec_path)
        except OSError:
            pass


def read_pid_file(pid_file: Any) -> int | None:
    try:
        with open(str(pid_file or ''), 'r', encoding='utf-8') as file_obj:
            pid = int(file_obj.read().strip())
        return pid if pid > 0 else None
    except Exception:
        return None


def is_windows_pid_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    still_active = 259
    error_access_denied = 5

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    get_exit_code_process = kernel32.GetExitCodeProcess
    get_exit_code_process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit_code_process.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        return ctypes.get_last_error() == error_access_denied
    try:
        exit_code = wintypes.DWORD()
        if not get_exit_code_process(handle, ctypes.byref(exit_code)):
            return False
        return int(exit_code.value) == still_active
    finally:
        close_handle(handle)


def is_pid_alive(pid: Any) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == 'nt':
        return is_windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def signal_process_group_or_pid(pid: int, sig: int):
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


def signal_name_to_value(value: Any) -> int:
    text = str(value or 'TERM').strip().upper()
    if not text.startswith('SIG'):
        text = 'SIG' + text
    return int(getattr(signal, text, signal.SIGTERM))


def stop_by_signal(pid: int | None, stop_spec: dict, default_timeout_sec: int = 5) -> dict:
    if not pid:
        return {'type': 'signal', 'signal': '', 'sent': False, 'message': 'pid not found'}
    sig = signal_name_to_value((stop_spec or {}).get('signal') or 'TERM')
    timeout_sec = int((stop_spec or {}).get('timeout_sec') or default_timeout_sec)
    kill_after_timeout = bool((stop_spec or {}).get('kill_after_timeout', True))
    signal_process_group_or_pid(pid, sig)
    deadline = time.time() + max(0.1, timeout_sec)
    while time.time() < deadline:
        if not is_pid_alive(pid):
            return {'type': 'signal', 'signal': signal.Signals(sig).name, 'sent': True, 'killed': False}
        time.sleep(0.1)
    killed = False
    if kill_after_timeout and is_pid_alive(pid):
        signal_process_group_or_pid(pid, signal.SIGKILL)
        killed = True
    return {'type': 'signal', 'signal': signal.Signals(sig).name, 'sent': True, 'killed': killed}


def write_stopped_state(state_file: str, stop_result: dict, stopped_at: str):
    from core.external_tools.files import read_json_file_or_empty

    state = read_json_file_or_empty(state_file)
    state['last_status'] = 'stopped'
    state['stopped_at'] = stopped_at
    state['stop_result'] = stop_result
    write_json_file(state_file, state)
