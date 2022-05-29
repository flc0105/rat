import inspect

import psutil
import pythoncom
import wmi


class ProcessMonitor:
    def __init__(self):
        self.status = False

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            setattr(cls, 'instance', cls())
        return getattr(cls, 'instance')

    @staticmethod
    def exec(pid, func):
        args = inspect.getfullargspec(func).args
        if not len(args):
            func()
        elif 'process' in args:
            func(process=pid)

    def watch(self, watcher, func):
        while self.status:
            try:
                process = watcher()
                if not self.status:
                    break
                self.exec(process.ProcessId, func)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def watch_list(self, watcher, processes, func):
        while self.status:
            try:
                process = watcher()
                if not self.status:
                    break
                if process.Name.lower() in processes:
                    self.exec(process.ProcessId, func)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def start(self, processes, func):
        self.status = True
        pythoncom.CoInitialize()
        if len(processes) == 1 and processes[0] != 'all':
            watcher = wmi.WMI().watch_for(
                notification_type='Creation',
                wmi_class='Win32_Process',
                name=processes[0]
            )
            self.watch(watcher, func)
        else:
            watcher = wmi.WMI().watch_for(
                notification_type='Creation',
                wmi_class='Win32_Process'
            )
            if len(processes) == 1:
                self.watch(watcher, func)
            else:
                self.watch_list(watcher, processes, func)

    def stop(self):
        self.status = False
