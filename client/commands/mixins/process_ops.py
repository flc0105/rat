# client/commands/mixins/process_ops.py

import os
import sys
import json
import platform
import psutil

from core.utils.decorator import desc


class CommandProcessMixin:

    @desc('List running processes', group='process', suggest=False)
    def list_processes(self, arg=''):
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

    @desc('Kill a process by PID', group='process', suggest=False)
    def kill_process(self, pid: str):
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