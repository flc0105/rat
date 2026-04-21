# client/commands/mixins/process_ops.py

import os
import sys
import json
import platform
from datetime import datetime

from core.platform.platform_identity import detect_platform_alias
from core.utils.decorator import desc


class CommandProcessMixin:

    @desc('List running processes', group='process', suggest=False)
    def list_processes(self, arg=''):
        import psutil
        """
        列出所有运行中的进程
        """
        try:
            processes = []
            # for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            for proc in psutil.process_iter(['pid', 'name', 'status']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'] or '',
                        # 'username': pinfo['username'] or '',
                        # 'cpu_percent': round(pinfo['cpu_percent'] or 0, 1),
                        # 'memory_percent': round(pinfo['memory_percent'] or 0, 1),
                        'status': pinfo['status'] or '',
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return 1, json.dumps(processes)
        except Exception as e:
            return 0, f'Failed to list processes: {e}'

    @desc('Get process detail by PID', group='process', suggest=False)
    def get_process_detail(self, arg=''):
        import psutil
        """
        获取单个进程详情，包括：
        - 基本信息
        - 文件路径 / 启动参数 / 工作目录
        - 网络连接
        - 打开的文件
        """
        try:
            pid = int(str(arg or '').strip())
        except Exception:
            return 0, 'PID is required'

        def _safe_call(getter, default=None):
            try:
                return getter()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return default
            except Exception:
                return default

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
                name = _safe_call(proc.name, '') or ''
                username = _safe_call(proc.username, '') or ''
                status = _safe_call(proc.status, '') or ''
                ppid = _safe_call(proc.ppid, None)
                exe = _safe_call(proc.exe, '') or ''
                cwd = _safe_call(proc.cwd, '') or ''
                cmdline = _safe_call(proc.cmdline, []) or []
                create_time = _safe_call(proc.create_time, None)
                cpu_percent = _safe_call(proc.cpu_percent, 0.0) or 0.0
                memory_percent = _safe_call(proc.memory_percent, 0.0) or 0.0
                num_threads = _safe_call(proc.num_threads, None)
                num_fds = _safe_call(lambda: getattr(proc, 'num_fds')(), None)
                num_handles = _safe_call(lambda: getattr(proc, 'num_handles')(), None)

            open_files = []
            for item in (_safe_call(proc.open_files, []) or []):
                open_files.append({
                    'path': getattr(item, 'path', '') or '',
                    'fd': getattr(item, 'fd', None),
                    'position': getattr(item, 'position', None),
                    'mode': getattr(item, 'mode', '') or '',
                    'flags': getattr(item, 'flags', None),
                })

            connections = []
            net_connections = _safe_call(lambda: proc.net_connections(kind='inet'), None)
            if net_connections is None:
                net_connections = _safe_call(lambda: proc.connections(kind='inet'), []) or []
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
            return 1, json.dumps(detail)
        except psutil.NoSuchProcess:
            return 0, f'Process {pid} not found'
        except Exception as e:
            return 0, f'Failed to get process detail: {e}'

    @desc('List running applications (GUI apps only)', group='process', suggest=False)
    def list_apps(self, arg=''):
        import psutil
        """
        列出运行中的应用程序（仅 GUI 应用）
        """
        try:
            apps = []

            def _safe_proc_value(getter, default=None):
                try:
                    return getter()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    return default
                except Exception:
                    return default

            current_platform = detect_platform_alias()
            if current_platform == 'win':
                # if platform.system() == 'Windows':
                # Windows: 获取有窗口的进程
                import win32gui
                import win32process

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
                            'name': _safe_proc_value(proc.name, '') or '',
                            # 'username': _safe_proc_value(proc.username, '') or '',
                            # 'exe': _safe_proc_value(proc.exe, '') or '',
                            # 'cwd': _safe_proc_value(proc.cwd, '') or '',
                            # 'cmdline': _safe_proc_value(proc.cmdline, []) or [],
                            'status': _safe_proc_value(proc.status, '') or '',
                        })
                    except Exception:
                        continue

            # elif platform.system() == 'Darwin':
            elif current_platform == 'mac':
                # macOS: 优先使用 System Events 获取真正的 GUI 应用进程（非 background only）
                import subprocess

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
                                # 'username': _safe_proc_value(proc.username, '') or '',
                                # 'exe': _safe_proc_value(proc.exe, '') or '',
                                # 'cwd': _safe_proc_value(proc.cwd, '') or '',
                                # 'cmdline': _safe_proc_value(proc.cmdline, []) or [],
                                'status': _safe_proc_value(proc.status, '') or '',
                                # 'frontmost': str(frontmost_text).lower() == 'true',
                            })

                    if parsed_apps:
                        parsed_apps.sort(
                            key=lambda item: (
                                # 0 if item.get('frontmost') else 1,
                                (item.get('name') or '').lower(),
                                item.get('pid') or 0,
                            )
                        )
                        apps = parsed_apps
                except Exception:
                    raise

            else:
                raise Exception('Unsupported os:' + str(current_platform))

            return 1, json.dumps(apps)
        except Exception as e:
            return 0, f'Failed to list apps: {e}'


    @desc('Kill a process by PID', group='process', suggest=False)
    def kill_process(self, pid: str):
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

            return 1, f'Process {pid} terminated'
        except psutil.NoSuchProcess:
            return 0, f'Process {pid} not found'
        except psutil.AccessDenied:
            return 0, f'Access denied to kill process {pid}'
        except Exception as e:
            return 0, f'Failed to kill process {pid}: {e}'
