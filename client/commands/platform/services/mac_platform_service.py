from client.commands.platform.services.mac.automation_service import MacAutomationService
from client.commands.platform.services.mac.file_inspection_service import MacFileInspectionService
from client.commands.platform.services.mac.media_service import MacMediaService
from client.commands.platform.services.mac.system_service import MacSystemService


class MacPlatformService:
    """
    macOS 平台能力 facade。

    当前只负责组合平台子服务，不再直接承载所有平台实现。
    """

    def __init__(self, owner):
        self.owner = owner
        self.system = MacSystemService(owner)
        self.media = MacMediaService(owner)
        self.automation = MacAutomationService(owner)
        self.file_inspection = MacFileInspectionService(owner)

    def run_command_text(self, command: str, timeout: int = 15) -> str:
        return self.system.run_command_text(command, timeout=timeout)

    def build_process_info(self):
        return self.system.build_process_info()

    def escape_osascript_text(self, value: str):
        return self.automation.escape_osascript_text(value)

    def spawn_osascript(self, applescript: str):
        return self.automation.spawn_osascript(applescript)

    # ------------------ 普通平台命令实现 ------------------ #
    def capture_screenshot(self):
        return self.media.capture_screenshot()

    def collect_system_info(self, arg=''):
        return self.system.collect_system_info(arg)

    def get_idle_time(self):
        return self.system.get_idle_time()

    def capture_webcam_photo(self):
        """拍照并上传到服务器"""
        return self.media.capture_webcam_photo()

    def sudo_self(self):
        """以 root 权限启动新实例，返回 PID"""
        return self.automation.sudo_self()

    def sudo_run(self, command):
        """以 root 权限执行命令 (macOS)"""
        return self.automation.sudo_run(command)

    def secure_delete_file(self, path):
        """安全删除文件（覆写后删除）"""
        return self.file_inspection.secure_delete_file(path)

    # ------------------ acmd 平台扩展实现 ------------------ #
    def acmd_msgbox(self, args_dict, payload=None):
        return self.automation.acmd_msgbox(args_dict, payload)

    def acmd_notify(self, args_dict, payload=None):
        return self.automation.acmd_notify(args_dict, payload)

    def acmd_sqlite_query(self, args_dict, payload=None):
        """
        只读 SQLite 查询
        Examples:
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_list;"
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_info('bookings')"
            acmd sqlite_query --db /Users/flc/studio.db --query "select * from scenes"
        """
        return self.file_inspection.acmd_sqlite_query(args_dict, payload)

    def acmd_image_info(self, args_dict, payload=None):
        """获取图片信息"""
        return self.file_inspection.acmd_image_info(args_dict, payload)

    def acmd_import_check(self, args_dict, payload=None):
        """检查 Python 包是否可以导入"""
        return self.file_inspection.acmd_import_check(args_dict, payload)

    def acmd_archive_peek(self, args_dict, payload=None):
        """查看压缩包内容"""
        return self.file_inspection.acmd_archive_peek(args_dict, payload)