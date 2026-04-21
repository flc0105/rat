import json
from datetime import datetime

from core.platform.platform_identity import detect_platform_alias


class ProcessService:

    def __init__(self, owner):
        self.owner = owner

    def list_processes(self):
        import psutil
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'] or '',
                    'status': pinfo['status'] or '',
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def _safe_proc_value(self, getter, default=None):
        import psutil
        try:
            return getter()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return default
        except Exception:
            return default

    def get_process_detail(self, pid):
        import psutil

        def _normalize_address(addr):
            if not addr:
                return ''
            if isinstance(addr, tuple):
                if len(addr) >= 2:
                    return f'{addr[0]}:{addr[1]}'
                return str(addr)
            ip = getattr(addr, 'ip', '')
            port = getattr(addr, 'port', '')
            if ip and port != '':
                return f'{ip}:{port}'
            if ip:
                return str(ip)
            return str(addr)

        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = self._safe_proc_value(proc.name, '') or ''
                username = self._safe_proc_value(proc.username, '') or ''
                status = self._safe_proc_value(proc.status, '') or ''
                ppid = self._safe_proc_value(proc.ppid, None)
                exe = self._safe_proc_value(proc.exe, '') or ''
                cwd = self._safe_proc_value(proc.cwd, '') or ''
                cmdline = self._safe_proc_value(proc.cmdline, []) or []
                create_time = self._safe_proc_value(proc.create_time, None)
                cpu_percent = self._safe_proc_value(proc.cpu_percent, 0.0) or 0.0
                memory_percent = self._safe_proc_value(proc.memory_percent, 0.0) or 0.0
                num_threads = self._safe_proc_value(proc.num_threads, None)
                num_fds = self._safe_proc_value(lambda: getattr(proc, 'num_fds')(), None)
                num_handles = self._safe_proc_value(lambda: getattr(proc, 'num_handles')(), None)

            open_files = []
            for item in (self._safe_proc_value(proc.open_files, []) or []):
                open_files.append({
                    'path': getattr(item, 'path', '') or '',
                    'fd': getattr(item, 'fd', None),
                    # 'position': getattr(item, 'position', None),
                    # 'mode': getattr(item, 'mode', '') or '',
                    # 'flags': getattr(item, 'flags', None),
                })

            connections = []
            net_connections = self._safe_proc_value(lambda: proc.net_connections(kind='inet'), None)
            if net_connections is None:
                net_connections = self._safe_proc_value(lambda: proc.connections(kind='inet'), []) or []
            for conn in net_connections:
                connections.append({
                    'fd': getattr(conn, 'fd', None),
                    'family': str(getattr(conn, 'family', '')),
                    'type': str(getattr(conn, 'type', '')),
                    'local_address': _normalize_address(getattr(conn, 'laddr', None)),
                    'remote_address': _normalize_address(getattr(conn, 'raddr', None)),
                    'status': getattr(conn, 'status', '') or '',
                })

            detail = {
                'pid': pid,
                'name': name,
                'username': username,
                'status': status,
                'ppid': ppid,
                'exe': exe,
                'cwd': cwd,
                'cmdline': cmdline,
                'create_time': datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S'),
                'cpu_percent': round(cpu_percent, 1),
                'memory_percent': round(memory_percent, 1),
                'num_threads': num_threads,
                'num_fds': num_fds,
                'num_handles': num_handles,
                'open_files': open_files,
                'connections': connections,
            }
            return detail
        except psutil.NoSuchProcess:
            raise Exception(f'Process {pid} not found')
        except Exception as e:
            raise Exception(f'Failed to get process detail: {e}')

    def list_windows_apps(self):
        import psutil
        import win32gui
        import win32process

        apps = []

        def enum_window_callback(hwnd, windows):
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid not in windows:
                    windows.append(pid)

        windows = []
        win32gui.EnumWindows(enum_window_callback, windows)

        for pid in windows:
            try:
                proc = psutil.Process(pid)
                apps.append({
                    'pid': pid,
                    'name': self._safe_proc_value(proc.name, '') or '',
                    'status': self._safe_proc_value(proc.status, '') or '',
                })
            except Exception:
                continue
        return apps

    def list_macos_app(self):
        import subprocess
        import psutil

        exclude_names = {
            'Finder',
            'Dock',
            'SystemUIServer',
            'NotificationCenter',
            'Spotlight',
            'Siri',
        }

        apple_script = r'''
                          tell application "System Events"
                              set outputLines to {}
                              set appProcs to every application process whose background only is false
                              repeat with proc in appProcs
                                  try
                                      set procPid to unix id of proc
                                      set procName to name of proc
                                      set procFrontmost to frontmost of proc
                                      set end of outputLines to ((procFrontmost as text) & tab & (procPid as text) & tab & procName)
                                  end try
                              end repeat
                              return outputLines
                          end tell
                          '''

        parsed_apps = []
        try:
            result = subprocess.run(
                ['osascript', '-e', apple_script],
                capture_output=True,
                text=True,
                timeout=5
            )

            stdout = (result.stdout or '').strip()
            if stdout:
                raw_lines = [item.strip() for item in stdout.split(',') if item.strip()]
                seen_pid = set()

                for line in raw_lines:
                    parts = [part.strip().strip('"') for part in line.split('\t')]
                    if len(parts) < 3:
                        continue

                    frontmost_text, pid_text, proc_name = parts[0], parts[1], parts[2]

                    try:
                        pid = int(pid_text)
                    except Exception:
                        continue

                    if pid in seen_pid:
                        continue
                    seen_pid.add(pid)

                    if not proc_name or proc_name in exclude_names or proc_name.startswith('com.'):
                        continue

                    try:
                        proc = psutil.Process(pid)
                    except Exception:
                        continue

                    parsed_apps.append({
                        'pid': pid,
                        'name': proc_name,
                        'status': self._safe_proc_value(proc.status, '') or '',
                    })

            if parsed_apps:
                parsed_apps.sort(
                    key=lambda item: (
                        (item.get('name') or '').lower(),
                        item.get('pid') or 0,
                    )
                )
                apps = parsed_apps
                return apps
        except Exception:
            raise

    def kill_process(self, pid):
        import psutil
        """
        终止进程
        """
        try:
            pid = int(pid.strip())
            proc = psutil.Process(pid)

            if detect_platform_alias() == 'win':
                proc.kill()
            else:
                proc.terminate()
                proc.wait(timeout=3)

        except psutil.NoSuchProcess:
            raise Exception(f'Process {pid} not found')
        except psutil.AccessDenied:
            raise Exception(f'Access denied to kill process {pid}')
        except Exception as e:
            raise Exception(f'Failed to kill process {pid}: {e}')