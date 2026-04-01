# client/commands/mixins/process_ops.py

import os
import sys
import json
import platform


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
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'] or '',
                        'username': pinfo['username'] or '',
                        'cpu_percent': round(pinfo['cpu_percent'] or 0, 1),
                        'memory_percent': round(pinfo['memory_percent'] or 0, 1),
                        'status': pinfo['status'] or '',
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return 1, json.dumps(processes)
        except Exception as e:
            return 0, f'Failed to list processes: {e}'

    @desc('List running applications (GUI apps only)', group='process', suggest=False)
    def list_apps(self, arg=''):
        import psutil
        """
        列出运行中的应用程序（仅 GUI 应用）
        """
        try:
            apps = []

            if platform.system() == 'Windows':
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
                            'name': proc.name(),
                            'username': proc.username(),
                        })
                    except:
                        continue

            elif platform.system() == 'Darwin':
                # macOS: 使用 Quartz 获取有窗口的应用
                try:
                    from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID

                    window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
                    app_dict = {}

                    for window in window_list:
                        pid = window.get('kCGWindowOwnerPID', 0)
                        if pid == 0:
                            continue
                        name = window.get('kCGWindowOwnerName', '')
                        if not name:
                            continue
                        if pid not in app_dict:
                            try:
                                proc = psutil.Process(pid)
                                app_dict[pid] = {
                                    'pid': pid,
                                    'name': name,
                                    'username': proc.username(),
                                }
                            except:
                                pass

                    apps = list(app_dict.values())
                except ImportError:
                    # 降级：返回所有进程
                    for proc in psutil.process_iter(['pid', 'name', 'username']):
                        try:
                            apps.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'] or '',
                                'username': proc.info['username'] or '',
                            })
                        except:
                            continue

            else:
                # Linux: 使用 psutil 获取所有进程
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        apps.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'] or '',
                            'username': proc.info['username'] or '',
                        })
                    except:
                        continue

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

            if platform.system() == 'Windows':
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





