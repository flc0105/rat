"""
_get_all_apps_info - 获取所有应用信息（包含窗口）

只比较 PID - 新启动判断基于 PID，不基于窗口

窗口只显示一次 - 在应用首次出现时（初始快照或新启动）显示窗口

窗口变化不触发 - 应用的窗口变化不会产生新通知

退出检测 - PID 消失时发送退出通知
"""
import os
import threading
import time

from client.jobs.core.job import Job
from core.utils.logger import logger


class AppLaunchMonitor(Job):
    def __init__(self, target_apps=None, interval=2):
        """
        应用启动监控器

        :param target_apps: 要监控的应用列表，None 表示监控所有应用
        :param interval: 检查间隔（秒）
        """
        super().__init__()
        self.target_apps = target_apps
        self.interval = interval
        self.running_apps = {}  # 记录当前运行的应用 {pid: {name, exe, windows}}
        self.initial_snapshot_sent = False

    def run(self):
        try:
            time.sleep(2)
            self.send_to_server(1, 'App launch monitor started', 0)

            try:
                from Quartz import (
                    CGWindowListCopyWindowInfo,
                    kCGWindowListOptionAll,
                    kCGNullWindowID
                )
            except ImportError:
                self.send_to_server(0, 'Quartz not available, install: pip install pyobjc-framework-Quartz', 0)
                self.mark_stopped()
                return

            self.mark_running()
            self.send_to_server(1, f'Monitoring apps (interval: {self.interval}s)', 0)
            if self.target_apps:
                self.send_to_server(1, f'Target apps: {", ".join(self.target_apps)}', 0)

            while not self.stop_event.is_set():
                self._check_app_changes()
                time.sleep(self.interval)

            self.send_to_server(1, 'App launch monitor stopped', 0)
        except Exception as e:
            self.send_to_server(0, f'App launch monitor error: {e}', 0)
        finally:
            self.mark_stopped()
            logger.info(f'Thread ended: {threading.current_thread().name}')
            self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)

    def stop(self, notify: bool = True):
        self.request_stop(notify=notify)

    def _is_system_process(self, app_name, exe_path):
        """判断是否为系统进程"""
        system_paths = [
            '/System/',
            '/usr/libexec/',
            '/usr/bin/',
            '/usr/sbin/',
            '/bin/',
            '/sbin/',
            '/Library/CoreServices/',
            '/System/Library/'
        ]

        system_names = [
            'WindowServer', 'kernel_task', 'launchd', 'loginwindow',
            'SystemUIServer', 'Dock', 'Finder', 'NotificationCenter',
            'Spotlight', 'coreaudiod', 'blued', 'distnoted', 'cfprefsd',
            'powerd', 'securityd', 'syslogd', 'usbd', 'warmd', 'mDNSResponder'
        ]

        for sys_path in system_paths:
            if exe_path.startswith(sys_path):
                return True

        for sys_name in system_names:
            if app_name == sys_name:
                return True

        if not exe_path.endswith('.app/Contents/MacOS/') and '.app' not in exe_path:
            return True

        return False

    def _get_app_exe_path(self, pid):
        """获取应用路径"""
        try:
            import psutil
            proc = psutil.Process(pid)
            return proc.exe() if os.path.exists(proc.exe()) else ''
        except:
            return ''

    def _get_all_apps_info(self):
        """获取所有运行中的应用信息（PID, 名称, 窗口）"""
        try:
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionAll,
                kCGNullWindowID
            )

            windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
            apps = {}

            for window in windows:
                pid = window.get('kCGWindowOwnerPID', 0)
                if pid == 0:
                    continue

                app_name = window.get('kCGWindowOwnerName', '')
                if not app_name:
                    continue

                title = window.get('kCGWindowName', '')
                if not title:
                    continue

                if pid not in apps:
                    apps[pid] = {
                        'pid': pid,
                        'name': app_name,
                        'windows': []
                    }

                if title and title not in apps[pid]['windows']:
                    apps[pid]['windows'].append(title)

            return apps
        except Exception as e:
            return {}

    def _should_monitor(self, app_name):
        """判断是否需要监控该应用"""
        if not self.target_apps:
            return True

        for target in self.target_apps:
            if target.lower() in app_name.lower():
                return True
        return False

    def _send_app_info(self, app_info, is_initial=False):
        """发送应用信息"""
        prefix = "[Current] " if is_initial else ""

        message_lines = []
        message_lines.append(f"{prefix}{app_info['name']} (PID: {app_info['pid']})")

        if app_info.get('exe'):
            message_lines.append(f"  Path: {app_info['exe']}")

        if app_info.get('windows'):
            windows_str = ', '.join(app_info['windows'][:3])
            if len(app_info['windows']) > 3:
                windows_str += f' (+{len(app_info["windows"]) - 3} more)'
            message_lines.append(f"  Windows: {windows_str}")

        self.send_to_server(1, '\n'.join(message_lines), 0)

    def _check_app_changes(self):
        """检查应用变化 - 只基于 PID 判断新启动和退出"""
        try:
            current_apps = self._get_all_apps_info()
            current_pids = set(current_apps.keys())
            previous_pids = set(self.running_apps.keys())

            # 首次运行，发送当前所有运行中的应用
            if not self.initial_snapshot_sent:
                self.send_to_server(1, '--- Currently running applications ---', 0)

                for pid, app_info in current_apps.items():
                    # 获取应用路径
                    exe = self._get_app_exe_path(pid)
                    app_info['exe'] = exe

                    # 过滤系统进程
                    if self._is_system_process(app_info['name'], exe):
                        continue

                    if not self._should_monitor(app_info['name']):
                        continue

                    self._send_app_info(app_info, is_initial=True)
                    self.running_apps[pid] = app_info

                if not current_pids:
                    self.send_to_server(1, 'No applications running', 0)

                self.send_to_server(1, '--- Monitoring for new apps ---', 0)
                self.initial_snapshot_sent = True
                return

            # 新启动的应用（PID 不在之前记录中）
            new_pids = current_pids - previous_pids

            for pid in new_pids:
                app_info = current_apps[pid]

                # 获取应用路径
                exe = self._get_app_exe_path(pid)
                app_info['exe'] = exe

                # 过滤系统进程
                if self._is_system_process(app_info['name'], exe):
                    continue

                if not self._should_monitor(app_info['name']):
                    continue

                self._send_app_info(app_info, is_initial=False)
                self.running_apps[pid] = app_info

            # 应用退出（PID 在之前记录中但不在当前）
            exited_pids = previous_pids - current_pids
            for pid in exited_pids:
                if pid in self.running_apps:
                    app_name = self.running_apps[pid].get('name', 'Unknown')
                    if self._should_monitor(app_name):
                        self.send_to_server(1, f'App exited: {app_name} (PID: {pid})', 0)
                    del self.running_apps[pid]

            # 注意：不处理窗口变化，避免重复通知

        except Exception as e:
            self.send_to_server(0, f'Check error: {e}', 0)



#第三版：应用和窗口分开，只根据pid判断，去掉窗口标题
# import os
# import threading
# import time
#
# from client.jobs.core.job import Job
# from core.utils.logger import logger
#
#
# class AppLaunchMonitor(Job):
#     def __init__(self, target_apps=None, interval=2):
#         """
#         应用启动监控器
#
#         :param target_apps: 要监控的应用列表，None 表示监控所有应用
#         :param interval: 检查间隔（秒）
#         """
#         super().__init__()
#         self.target_apps = target_apps
#         self.interval = interval
#         self.running_apps = {}  # 记录当前运行的应用 {pid: info}
#         self.initial_snapshot_sent = False  # 是否已发送初始快照
#
#     def run(self):
#         try:
#             time.sleep(2)
#             self.send_to_server(1, 'App launch monitor started', 0)
#
#             # 检查 Quartz 是否可用
#             try:
#                 from Quartz import (
#                     CGWindowListCopyWindowInfo,
#                     kCGWindowListOptionAll,
#                     kCGNullWindowID
#                 )
#             except ImportError:
#                 self.send_to_server(0, 'Quartz not available, install: pip install pyobjc-framework-Quartz', 0)
#                 self.mark_stopped()
#                 return
#
#             self.mark_running()
#             self.send_to_server(1, f'Monitoring apps (interval: {self.interval}s)', 0)
#             if self.target_apps:
#                 self.send_to_server(1, f'Target apps: {", ".join(self.target_apps)}', 0)
#
#             while not self.stop_event.is_set():
#                 self._check_app_changes()
#                 time.sleep(self.interval)
#
#             self.send_to_server(1, 'App launch monitor stopped', 0)
#         except Exception as e:
#             self.send_to_server(0, f'App launch monitor error: {e}', 0)
#         finally:
#             self.mark_stopped()
#             logger.info(f'Thread ended: {threading.current_thread().name}')
#             self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)
#
#     def stop(self, notify: bool = True):
#         self.request_stop(notify=notify)
#
#     def _is_system_process(self, app_name, exe_path):
#         """判断是否为系统进程"""
#         system_paths = [
#             '/System/',
#             '/usr/libexec/',
#             '/usr/bin/',
#             '/usr/sbin/',
#             '/bin/',
#             '/sbin/',
#             '/Library/CoreServices/',
#             '/System/Library/'
#         ]
#
#         system_names = [
#             'WindowServer', 'kernel_task', 'launchd', 'loginwindow',
#             'SystemUIServer', 'Dock', 'Finder', 'NotificationCenter',
#             'Spotlight', 'coreaudiod', 'blued', 'distnoted', 'cfprefsd',
#             'powerd', 'securityd', 'syslogd', 'usbd', 'warmd', 'mDNSResponder'
#         ]
#
#         for sys_path in system_paths:
#             if exe_path.startswith(sys_path):
#                 return True
#
#         for sys_name in system_names:
#             if app_name == sys_name:
#                 return True
#
#         if not exe_path.endswith('.app/Contents/MacOS/') and '.app' not in exe_path:
#             return True
#
#         return False
#
#     def _get_app_info(self, pid, name, exe=''):
#         """获取应用基本信息"""
#         return {
#             'pid': pid,
#             'name': name,
#             'exe': exe
#         }
#
#     def _get_app_exe_path(self, pid):
#         """获取应用路径"""
#         try:
#             import psutil
#             proc = psutil.Process(pid)
#             return proc.exe() if os.path.exists(proc.exe()) else ''
#         except:
#             return ''
#
#     def _get_running_app_pids(self):
#         """只获取运行中的应用 PID（去重）"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             app_pids = set()
#
#             for window in windows:
#                 pid = window.get('kCGWindowOwnerPID', 0)
#                 if pid == 0:
#                     continue
#
#                 app_name = window.get('kCGWindowOwnerName', '')
#                 if not app_name:
#                     continue
#
#                 title = window.get('kCGWindowName', '')
#                 if not title:
#                     continue
#
#                 app_pids.add(pid)
#
#             return app_pids
#         except Exception as e:
#             return set()
#
#     def _get_app_name_and_windows(self, pid):
#         """获取应用的名称和窗口列表"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             app_name = ''
#             window_titles = []
#
#             for window in windows:
#                 window_pid = window.get('kCGWindowOwnerPID', 0)
#                 if window_pid == pid:
#                     if not app_name:
#                         app_name = window.get('kCGWindowOwnerName', '')
#                     title = window.get('kCGWindowName', '')
#                     if title:
#                         window_titles.append(title)
#
#             return app_name, window_titles
#         except:
#             return '', []
#
#     def _should_monitor(self, app_name):
#         """判断是否需要监控该应用"""
#         if not self.target_apps:
#             return True
#
#         for target in self.target_apps:
#             if target.lower() in app_name.lower():
#                 return True
#         return False
#
#     def _send_app_info(self, pid, app_name, exe, is_initial=False):
#         """发送应用信息"""
#         prefix = "[Current] " if is_initial else ""
#
#         message_lines = []
#         message_lines.append(f"{prefix}{app_name} (PID: {pid})")
#
#         if exe:
#             message_lines.append(f"  Path: {exe}")
#
#         self.send_to_server(1, '\n'.join(message_lines), 0)
#
#     def _check_app_changes(self):
#         """检查应用变化 - 只关注 PID 的变化"""
#         try:
#             current_pids = self._get_running_app_pids()
#             previous_pids = set(self.running_apps.keys())
#
#             # 首次运行，发送当前所有运行中的应用
#             if not self.initial_snapshot_sent:
#                 self.send_to_server(1, '--- Currently running applications ---', 0)
#
#                 for pid in current_pids:
#                     app_name, _ = self._get_app_name_and_windows(pid)
#                     if not app_name:
#                         continue
#
#                     exe = self._get_app_exe_path(pid)
#
#                     # 过滤系统进程
#                     if self._is_system_process(app_name, exe):
#                         continue
#
#                     if not self._should_monitor(app_name):
#                         continue
#
#                     self._send_app_info(pid, app_name, exe, is_initial=True)
#                     self.running_apps[pid] = {
#                         'name': app_name,
#                         'exe': exe
#                     }
#
#                 if not current_pids:
#                     self.send_to_server(1, 'No applications running', 0)
#
#                 self.send_to_server(1, '--- Monitoring for new apps ---', 0)
#                 self.initial_snapshot_sent = True
#                 return
#
#             # 新启动的应用（PID 不在之前记录中）
#             new_pids = current_pids - previous_pids
#
#             for pid in new_pids:
#                 app_name, _ = self._get_app_name_and_windows(pid)
#                 if not app_name:
#                     continue
#
#                 exe = self._get_app_exe_path(pid)
#
#                 # 过滤系统进程
#                 if self._is_system_process(app_name, exe):
#                     continue
#
#                 if not self._should_monitor(app_name):
#                     continue
#
#                 self._send_app_info(pid, app_name, exe, is_initial=False)
#                 self.running_apps[pid] = {
#                     'name': app_name,
#                     'exe': exe
#                 }
#
#             # 应用退出（PID 在之前记录中但不在当前）
#             exited_pids = previous_pids - current_pids
#             for pid in exited_pids:
#                 if pid in self.running_apps:
#                     app_name = self.running_apps[pid].get('name', 'Unknown')
#                     if self._should_monitor(app_name):
#                         self.send_to_server(1, f'App exited: {app_name} (PID: {pid})', 0)
#                     del self.running_apps[pid]
#
#         except Exception as e:
#             self.send_to_server(0, f'Check error: {e}', 0)

#第二版：显示文件和连接列表
# import os
# import threading
# import time
# import json
#
# from client.jobs.core.job import Job
# from core.utils.logger import logger
#
#
# class AppLaunchMonitor(Job):
#     def __init__(self, target_apps=None, interval=2):
#         """
#         应用启动监控器
#
#         :param target_apps: 要监控的应用列表，None 表示监控所有应用
#         :param interval: 检查间隔（秒）
#         """
#         super().__init__()
#         self.target_apps = target_apps  # 例如 ['WeChat', 'Google Chrome', 'Terminal']
#         self.interval = interval
#         self.running_apps = {}  # 记录当前运行的应用 {pid: info}
#         self.recent_launches = set()  # 记录最近已通知的启动，避免重复
#
#     def run(self):
#         try:
#             time.sleep(2)
#             self.send_to_server(1, 'App launch monitor started', 0)
#
#             # 检查 Quartz 是否可用
#             try:
#                 from Quartz import (
#                     CGWindowListCopyWindowInfo,
#                     kCGWindowListOptionAll,
#                     kCGNullWindowID
#                 )
#                 self.send_to_server(1, 'Quartz loaded successfully', 0)
#             except ImportError:
#                 self.send_to_server(0, 'Quartz not available, install: pip install pyobjc-framework-Quartz', 0)
#                 self.mark_stopped()
#                 return
#
#             self.mark_running()
#             self.send_to_server(1, f'Monitoring apps (interval: {self.interval}s)', 0)
#             if self.target_apps:
#                 self.send_to_server(1, f'Target apps: {", ".join(self.target_apps)}', 0)
#
#             while not self.stop_event.is_set():
#                 self._check_app_launches()
#                 time.sleep(self.interval)
#
#             self.send_to_server(1, 'App launch monitor stopped', 0)
#         except Exception as e:
#             self.send_to_server(0, f'App launch monitor error: {e}', 0)
#         finally:
#             self.mark_stopped()
#             logger.info(f'Thread ended: {threading.current_thread().name}')
#             self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)
#
#     def stop(self, notify: bool = True):
#         self.request_stop(notify=notify)
#
#     def _is_system_process(self, app_name, exe_path):
#         """判断是否为系统进程"""
#         system_paths = [
#             '/System/',
#             '/usr/libexec/',
#             '/usr/bin/',
#             '/usr/sbin/',
#             '/bin/',
#             '/sbin/',
#             '/Library/CoreServices/',
#             '/System/Library/'
#         ]
#
#         # 系统进程名称关键字
#         system_names = [
#             'WindowServer', 'kernel_task', 'launchd', 'loginwindow',
#             'SystemUIServer', 'Dock', 'Finder', 'NotificationCenter',
#             'Spotlight', 'coreaudiod', 'blued', 'distnoted', 'cfprefsd',
#             'powerd', 'securityd', 'syslogd', 'usbd', 'warmd', 'mDNSResponder'
#         ]
#
#         # 检查路径
#         for sys_path in system_paths:
#             if exe_path.startswith(sys_path):
#                 return True
#
#         # 检查名称
#         for sys_name in system_names:
#             if app_name == sys_name:
#                 return True
#
#         # 检查是否是 .app 应用（不是.app的通常是后台进程）
#         if not exe_path.endswith('.app/Contents/MacOS/') and '.app' not in exe_path:
#             return True
#
#         return False
#
#     def _get_app_process_info(self, pid):
#         """获取进程详细信息"""
#         try:
#             import psutil
#
#             proc = psutil.Process(pid)
#             info = {
#                 'pid': pid,
#                 'name': proc.name(),
#                 'exe': proc.exe() if os.path.exists(proc.exe()) else '',
#                 'cwd': proc.cwd() if os.path.exists(proc.cwd()) else '',
#                 'cmdline': ' '.join(proc.cmdline()),
#                 'create_time': proc.create_time(),
#                 'username': proc.username(),
#                 'status': proc.status(),
#             }
#
#             # 获取打开的文件（显示具体文件名）
#             try:
#                 files = []
#                 for f in proc.open_files():
#                     # 只显示文件名，不显示完整路径（避免过长）
#                     file_path = f.path
#                     # 如果路径太长，只显示最后一部分
#                     if len(file_path) > 60:
#                         file_path = '...' + file_path[-57:]
#                     files.append(file_path)
#                 info['open_files'] = files[:10]  # 最多10个
#                 info['open_files_count'] = len(proc.open_files())
#             except:
#                 info['open_files'] = []
#                 info['open_files_count'] = 0
#
#             # 获取网络连接
#             try:
#                 connections = []
#                 for conn in proc.connections():
#                     if conn.laddr:
#                         conn_str = f"{conn.laddr.ip}:{conn.laddr.port}"
#                         if conn.raddr:
#                             conn_str += f" -> {conn.raddr.ip}:{conn.raddr.port}"
#                         connections.append(conn_str)
#                 info['connections'] = connections[:5]  # 最多5个
#                 info['connections_count'] = len(proc.connections())
#             except:
#                 info['connections'] = []
#                 info['connections_count'] = 0
#
#             # 获取内存使用
#             try:
#                 info['memory_mb'] = round(proc.memory_info().rss / 1024 / 1024, 2)
#             except:
#                 info['memory_mb'] = 0
#
#             # 获取 CPU 使用率
#             try:
#                 info['cpu_percent'] = proc.cpu_percent(interval=0.1)
#             except:
#                 info['cpu_percent'] = 0
#
#             return info
#
#         except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
#             return None
#         except Exception as e:
#             return None
#
#     def _get_app_window_titles(self, pid):
#         """获取指定应用的所有窗口标题"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             titles = []
#
#             for window in windows:
#                 window_pid = window.get('kCGWindowOwnerPID', 0)
#                 if window_pid == pid:
#                     title = window.get('kCGWindowName', '')
#                     if title:
#                         titles.append(title)
#
#             return titles[:10]
#         except:
#             return []
#
#     def _get_running_apps(self):
#         """获取当前运行的应用列表（只包含有窗口的图形应用）"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             apps = {}
#
#             for window in windows:
#                 pid = window.get('kCGWindowOwnerPID', 0)
#                 if pid == 0:
#                     continue
#
#                 app_name = window.get('kCGWindowOwnerName', '')
#                 if not app_name:
#                     continue
#
#                 # 只记录有窗口的应用
#                 title = window.get('kCGWindowName', '')
#                 if not title:
#                     continue
#
#                 if pid not in apps:
#                     apps[pid] = {
#                         'pid': pid,
#                         'name': app_name,
#                         'windows': []
#                     }
#
#                 if title:
#                     apps[pid]['windows'].append(title)
#
#             return apps
#         except Exception as e:
#             return {}
#
#     def _should_monitor(self, app_name):
#         """判断是否需要监控该应用"""
#         if not self.target_apps:
#             return True
#
#         for target in self.target_apps:
#             if target.lower() in app_name.lower():
#                 return True
#         return False
#
#     def _check_app_launches(self):
#         """检查新启动的应用"""
#         try:
#             current_apps = self._get_running_apps()
#             current_pids = set(current_apps.keys())
#             previous_pids = set(self.running_apps.keys())
#
#             # 新启动的应用
#             new_pids = current_pids - previous_pids
#
#             for pid in new_pids:
#                 app_info = current_apps[pid]
#                 app_name = app_info['name']
#
#                 # 获取详细信息
#                 proc_info = self._get_app_process_info(pid)
#                 if not proc_info:
#                     continue
#
#                 # 过滤系统进程
#                 if self._is_system_process(app_name, proc_info.get('exe', '')):
#                     continue
#
#                 if not self._should_monitor(app_name):
#                     continue
#
#                 # 获取窗口标题
#                 window_titles = app_info.get('windows', [])
#
#                 # 构建一条完整的消息
#                 message_lines = []
#                 message_lines.append(f"App launched: {app_name} (PID: {pid})")
#
#                 if proc_info.get('exe'):
#                     message_lines.append(f"  Path: {proc_info['exe']}")
#
#                 if window_titles:
#                     titles_str = ', '.join(window_titles[:3])
#                     if len(window_titles) > 3:
#                         titles_str += f' (+{len(window_titles) - 3} more)'
#                     message_lines.append(f"  Windows: {titles_str}")
#
#                 # 显示打开的文件
#                 if proc_info.get('open_files'):
#                     open_files = proc_info['open_files']
#                     total_count = proc_info.get('open_files_count', len(open_files))
#                     message_lines.append(f"  Open files ({total_count} total):")
#                     for f in open_files[:5]:
#                         message_lines.append(f"    - {f}")
#                     if len(open_files) < total_count:
#                         message_lines.append(f"    ... and {total_count - len(open_files)} more")
#
#                 # 显示连接信息
#                 if proc_info.get('connections'):
#                     connections = proc_info['connections']
#                     total_conn = proc_info.get('connections_count', len(connections))
#                     message_lines.append(f"  Connections ({total_conn} total):")
#                     for conn in connections[:3]:
#                         message_lines.append(f"    - {conn}")
#                     if len(connections) < total_conn:
#                         message_lines.append(f"    ... and {total_conn - len(connections)} more")
#
#                 if proc_info.get('memory_mb'):
#                     message_lines.append(f"  Memory: {proc_info['memory_mb']} MB")
#
#                 if proc_info.get('cpu_percent'):
#                     message_lines.append(f"  CPU: {proc_info['cpu_percent']}%")
#
#                 if proc_info.get('username'):
#                     message_lines.append(f"  User: {proc_info['username']}")
#
#                 # 发送一条消息
#                 self.send_to_server(1, '\n'.join(message_lines), 0)
#
#                 # 避免短时间内重复通知
#                 app_key = f"{app_name}_{pid}"
#                 self.recent_launches.add(app_key)
#
#                 # 清理旧的记录（保留最近100个）
#                 if len(self.recent_launches) > 100:
#                     self.recent_launches.clear()
#
#             # 应用退出
#             exited_pids = previous_pids - current_pids
#             for pid in exited_pids:
#                 if pid in self.running_apps:
#                     app_name = self.running_apps[pid].get('name', 'Unknown')
#                     if not self._should_monitor(app_name):
#                         continue
#                     self.send_to_server(1, f'App exited: {app_name} (PID: {pid})', 0)
#
#             # 更新记录
#             self.running_apps = current_apps
#
#         except Exception as e:
#             self.send_to_server(0, f'Check error: {e}', 0)

# 第一版
# import os
# import threading
# import time
# import json
#
# from client.jobs.core.job import Job
# from core.utils.logger import logger
#
#
# class AppLaunchMonitor(Job):
#     def __init__(self, target_apps=None, interval=2):
#         """
#         应用启动监控器
#
#         :param target_apps: 要监控的应用列表，None 表示监控所有应用
#         :param interval: 检查间隔（秒）
#         """
#         super().__init__()
#         self.target_apps = target_apps  # 例如 ['WeChat', 'Google Chrome', 'Terminal']
#         self.interval = interval
#         self.running_apps = {}  # 记录当前运行的应用 {pid: info}
#         self.recent_launches = set()  # 记录最近已通知的启动，避免重复
#
#     def run(self):
#         try:
#             time.sleep(2)
#             self.send_to_server(1, 'App launch monitor started', 0)
#
#             # 检查 Quartz 是否可用
#             try:
#                 from Quartz import (
#                     CGWindowListCopyWindowInfo,
#                     kCGWindowListOptionAll,
#                     kCGNullWindowID
#                 )
#                 self.send_to_server(1, 'Quartz loaded successfully', 0)
#             except ImportError:
#                 self.send_to_server(0, 'Quartz not available, install: pip install pyobjc-framework-Quartz', 0)
#                 self.mark_stopped()
#                 return
#
#             self.mark_running()
#             self.send_to_server(1, f'Monitoring apps (interval: {self.interval}s)', 0)
#             if self.target_apps:
#                 self.send_to_server(1, f'Target apps: {", ".join(self.target_apps)}', 0)
#
#             while not self.stop_event.is_set():
#                 self._check_app_launches()
#                 time.sleep(self.interval)
#
#             self.send_to_server(1, 'App launch monitor stopped', 0)
#         except Exception as e:
#             self.send_to_server(0, f'App launch monitor error: {e}', 0)
#         finally:
#             self.mark_stopped()
#             logger.info(f'Thread ended: {threading.current_thread().name}')
#             self.send_to_server(1, f'Task ended: {threading.current_thread().name}', 1)
#
#     def stop(self, notify: bool = True):
#         self.request_stop(notify=notify)
#
#     def _is_system_process(self, app_name, exe_path):
#         """判断是否为系统进程"""
#         system_paths = [
#             '/System/',
#             '/usr/libexec/',
#             '/usr/bin/',
#             '/usr/sbin/',
#             '/bin/',
#             '/sbin/',
#             '/Library/CoreServices/',
#             '/System/Library/'
#         ]
#
#         # 系统进程名称关键字
#         system_names = [
#             'WindowServer', 'kernel_task', 'launchd', 'loginwindow',
#             'SystemUIServer', 'Dock', 'Finder', 'NotificationCenter',
#             'Spotlight', 'coreaudiod', 'blued', 'distnoted', 'cfprefsd',
#             'powerd', 'securityd', 'syslogd', 'usbd', 'warmd', 'mDNSResponder'
#         ]
#
#         # 检查路径
#         for sys_path in system_paths:
#             if exe_path.startswith(sys_path):
#                 return True
#
#         # 检查名称
#         for sys_name in system_names:
#             if app_name == sys_name:
#                 return True
#
#         # 检查是否是 .app 应用（不是.app的通常是后台进程）
#         if not exe_path.endswith('.app/Contents/MacOS/') and '.app' not in exe_path:
#             return True
#
#         return False
#
#     def _get_app_process_info(self, pid):
#         """获取进程详细信息"""
#         try:
#             import psutil
#
#             proc = psutil.Process(pid)
#             info = {
#                 'pid': pid,
#                 'name': proc.name(),
#                 'exe': proc.exe() if os.path.exists(proc.exe()) else '',
#                 'cwd': proc.cwd() if os.path.exists(proc.cwd()) else '',
#                 'cmdline': ' '.join(proc.cmdline()),
#                 'create_time': proc.create_time(),
#                 'username': proc.username(),
#                 'status': proc.status(),
#             }
#
#             # 获取打开的文件
#             try:
#                 files = []
#                 for f in proc.open_files():
#                     files.append(f.path)
#                 info['open_files'] = files[:20]
#             except:
#                 info['open_files'] = []
#
#             # 获取网络连接
#             try:
#                 connections = []
#                 for conn in proc.connections():
#                     if conn.laddr:
#                         connections.append(f"{conn.laddr.ip}:{conn.laddr.port}")
#                 info['connections'] = connections[:10]
#             except:
#                 info['connections'] = []
#
#             # 获取内存使用
#             try:
#                 info['memory_mb'] = round(proc.memory_info().rss / 1024 / 1024, 2)
#             except:
#                 info['memory_mb'] = 0
#
#             # 获取 CPU 使用率
#             try:
#                 info['cpu_percent'] = proc.cpu_percent(interval=0.1)
#             except:
#                 info['cpu_percent'] = 0
#
#             return info
#
#         except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
#             return None
#         except Exception as e:
#             return None
#
#     def _get_app_window_titles(self, pid):
#         """获取指定应用的所有窗口标题"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             titles = []
#
#             for window in windows:
#                 window_pid = window.get('kCGWindowOwnerPID', 0)
#                 if window_pid == pid:
#                     title = window.get('kCGWindowName', '')
#                     if title:
#                         titles.append(title)
#
#             return titles[:10]
#         except:
#             return []
#
#     def _get_running_apps(self):
#         """获取当前运行的应用列表（只包含有窗口的图形应用）"""
#         try:
#             from Quartz import (
#                 CGWindowListCopyWindowInfo,
#                 kCGWindowListOptionAll,
#                 kCGNullWindowID
#             )
#
#             windows = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)
#             apps = {}
#
#             for window in windows:
#                 pid = window.get('kCGWindowOwnerPID', 0)
#                 if pid == 0:
#                     continue
#
#                 app_name = window.get('kCGWindowOwnerName', '')
#                 if not app_name:
#                     continue
#
#                 # 只记录有窗口的应用
#                 title = window.get('kCGWindowName', '')
#                 if not title:
#                     continue
#
#                 if pid not in apps:
#                     apps[pid] = {
#                         'pid': pid,
#                         'name': app_name,
#                         'windows': []
#                     }
#
#                 if title:
#                     apps[pid]['windows'].append(title)
#
#             return apps
#         except Exception as e:
#             return {}
#
#     def _should_monitor(self, app_name):
#         """判断是否需要监控该应用"""
#         if not self.target_apps:
#             return True
#
#         for target in self.target_apps:
#             if target.lower() in app_name.lower():
#                 return True
#         return False
#
#     def _check_app_launches(self):
#         """检查新启动的应用"""
#         try:
#             current_apps = self._get_running_apps()
#             current_pids = set(current_apps.keys())
#             previous_pids = set(self.running_apps.keys())
#
#             # 新启动的应用
#             new_pids = current_pids - previous_pids
#
#             for pid in new_pids:
#                 app_info = current_apps[pid]
#                 app_name = app_info['name']
#
#                 # 获取详细信息
#                 proc_info = self._get_app_process_info(pid)
#                 if not proc_info:
#                     continue
#
#                 # 过滤系统进程
#                 if self._is_system_process(app_name, proc_info.get('exe', '')):
#                     continue
#
#                 if not self._should_monitor(app_name):
#                     continue
#
#                 # 获取窗口标题
#                 window_titles = app_info.get('windows', [])
#
#                 # 构建一条完整的消息
#                 message_lines = []
#                 message_lines.append(f"App launched: {app_name} (PID: {pid})")
#
#                 if proc_info.get('exe'):
#                     message_lines.append(f"  Path: {proc_info['exe']}")
#
#                 if window_titles:
#                     message_lines.append(f"  Windows: {', '.join(window_titles[:3])}")
#
#                 if proc_info.get('open_files'):
#                     message_lines.append(f"  Open files: {len(proc_info['open_files'])} files")
#
#                 if proc_info.get('connections'):
#                     message_lines.append(f"  Connections: {len(proc_info['connections'])} connections")
#
#                 if proc_info.get('memory_mb'):
#                     message_lines.append(f"  Memory: {proc_info['memory_mb']} MB")
#
#                 if proc_info.get('cpu_percent'):
#                     message_lines.append(f"  CPU: {proc_info['cpu_percent']}%")
#
#                 if proc_info.get('username'):
#                     message_lines.append(f"  User: {proc_info['username']}")
#
#                 # 发送一条消息
#                 self.send_to_server(1, '\n'.join(message_lines), 0)
#
#                 # 避免短时间内重复通知
#                 app_key = f"{app_name}_{pid}"
#                 self.recent_launches.add(app_key)
#
#                 # 清理旧的记录（保留最近100个）
#                 if len(self.recent_launches) > 100:
#                     self.recent_launches.clear()
#
#             # 应用退出
#             exited_pids = previous_pids - current_pids
#             for pid in exited_pids:
#                 if pid in self.running_apps:
#                     app_name = self.running_apps[pid].get('name', 'Unknown')
#                     if not self._should_monitor(app_name):
#                         continue
#                     self.send_to_server(1, f'App exited: {app_name} (PID: {pid})', 0)
#
#             # 更新记录
#             self.running_apps = current_apps
#
#         except Exception as e:
#             self.send_to_server(0, f'Check error: {e}', 0)