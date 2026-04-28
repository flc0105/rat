from client.commands.platform.services.win.media_service import WinMediaService
from client.commands.platform.services.win.privilege_service import WinPrivilegeService
from client.commands.platform.services.win.process_service import WinProcessService
from client.commands.platform.services.win.system_service import WinSystemService


class WinPlatformService:
    """
    Windows 平台能力 facade。

    这里只组合平台子服务，具体实现放到 services/win/*。
    """

    def __init__(self, owner):
        self.owner = owner
        self.process = WinProcessService(owner)
        self.system = WinSystemService(owner)
        self.media = WinMediaService(owner)
        self.privilege = WinPrivilegeService(owner)

    def run(self, command):
        return self.process.run(command)

    def collect_system_info(self):
        return self.system.collect_system_info()

    def capture_screenshot(self):
        return self.media.capture_screenshot()

    def get_user_idletime(self):
        return self.system.get_user_idletime()

    def run_as_admin(self, command):
        return self.privilege.run_as_admin(command)