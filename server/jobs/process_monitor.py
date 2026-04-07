import inspect
import threading
import time

import psutil
import pythoncom
import wmi

from client.jobs.core.job import Job
from core.utils.logger import logger


class ProcessMonitor(Job):
    def __init__(self, target_processes=None):
        """
        Windows 进程启动监控器

        :param target_processes: 要监控的进程列表
                                 ['all'] 表示监控全部
                                 ['notepad.exe'] 表示只监控指定进程
                                 ['notepad.exe', 'calc.exe'] 表示监控多个指定进程
        """
        super().__init__()
        self.target_processes = target_processes or ['all']
        self.status = False

    def run(self):
        try:
            time.sleep(2)
            self.send_to_server(1, 'Process launch monitor started', 0)

            self.mark_running()
            self.status = True

            self.send_to_server(1, 'Monitoring process creation events', 0)
            if self.target_processes:
                self.send_to_server(1, f'Target processes: {", ".join(self.target_processes)}', 0)

            pythoncom.CoInitialize()

            if len(self.target_processes) == 1 and self.target_processes[0] != 'all':
                watcher = wmi.WMI().watch_for(
                    notification_type='Creation',
                    wmi_class='Win32_Process',
                    name=self.target_processes[0]
                )
                self._watch(watcher)
            else:
                watcher = wmi.WMI().watch_for(
                    notification_type='Creation',
                    wmi_class='Win32_Process'
                )
                if len(self.target_processes) == 1:
                    self._watch(watcher)
                else:
                    self._watch_list(watcher)

            self.send_to_server(1, 'Process launch monitor stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'Process launch monitor error: {e}', 0)
        finally:
            self.status = False
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self, notify: bool = True):
        self.request_stop(notify=notify)
        self.status = False

    @staticmethod
    def _is_system_process(process_name, exe_path=''):
        process_name = (process_name or '').lower()
        exe_path = (exe_path or '').lower()

        system_names = {
            'system',
            'system idle process',
            'registry',
            'smss.exe',
            'csrss.exe',
            'wininit.exe',
            'services.exe',
            'lsass.exe',
            'svchost.exe',
            'fontdrvhost.exe',
            'dwm.exe',
            'winlogon.exe',
            'memory compression',
            'sihost.exe',
            'taskhostw.exe',
            'runtimebroker.exe',
            'searchindexer.exe',
            'wudfhost.exe',
            'spoolsv.exe'
        }

        system_paths = (
            r'c:\windows\system32',
            r'c:\windows\syswow64',
            r'c:\windows\winsxs',
            r'c:\windows\servicing',
            r'c:\windows\systemapps'
        )

        if process_name in system_names:
            return True

        for sys_path in system_paths:
            if exe_path.startswith(sys_path):
                return True

        return False

    @staticmethod
    def _get_exe_path(pid):
        try:
            return psutil.Process(pid).exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ''
        except Exception:
            return ''

    def _send_process_info(self, pid, name):
        exe_path = self._get_exe_path(pid)

        if self._is_system_process(name, exe_path):
            return

        lines = [f'{name} (PID: {pid})']
        if exe_path:
            lines.append(f'  Path: {exe_path}')

        self.send_to_server(1, '\n'.join(lines), 0)

    def _watch(self, watcher):
        while self.status and not self.stop_event.is_set():
            try:
                process = watcher()
                if not self.status or self.stop_event.is_set():
                    break

                self._send_process_info(process.ProcessId, process.Name)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def _watch_list(self, watcher):
        processes = [p.lower() for p in self.target_processes]

        while self.status and not self.stop_event.is_set():
            try:
                process = watcher()
                if not self.status or self.stop_event.is_set():
                    break

                if process.Name.lower() in processes:
                    self._send_process_info(process.ProcessId, process.Name)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass