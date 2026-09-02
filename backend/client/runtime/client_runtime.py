from client.commands.runtime.executor import CommandExecutor
from client.jobs.core.manager import JobManager
from client.pty.manager import PtyManager
from client.screen.manager import ScreenViewManager
from client.clipboard.manager import ClipboardManager
from client.monitor.manager import DeviceMonitorManager


class ClientRuntime:
    """
    Client 端运行时能力容器。

    只负责持有和协调客户端本地运行能力：
    - command_executor：shell-like / script / acmd 三类命令入口
    - job_manager：后台任务运行态
    - pty_manager：交互式 PTY 会话
    - screen_view_manager：只读屏幕预览会话
    - clipboard_manager：显式远程剪贴板桥接
    - device_monitor_manager：按需实时设备监控会话
    """

    def __init__(self, connection):
        self.connection = connection
        self.command_executor = CommandExecutor(connection)
        self.job_manager = JobManager(connection)
        self.pty_manager = PtyManager(connection)
        self.screen_view_manager = ScreenViewManager(connection)
        self.clipboard_manager = ClipboardManager(connection)
        self.device_monitor_manager = DeviceMonitorManager(connection)

    def handle_connection_lost(self) -> list[str]:
        """
        连接断开时清理依赖服务端连接的运行态。
        """
        stopped_jobs = self.job_manager.handle_connection_lost()
        self.pty_manager.close_all_sessions(notify=False)
        self.screen_view_manager.close_all_sessions(notify=False)
        self.device_monitor_manager.close_all_sessions(notify=False)
        return stopped_jobs