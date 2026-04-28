from client.commands.argument_command_registry import argument_command
from client.commands.common import CommonCommands
from client.commands.interrupts import timeout, interruptible
from client.commands.platform.services.ios_platform_service import iOSPlatformService
from client.commands.platform.specs.ios import *
from core.utils.decorator import desc


class iOSCommands(CommonCommands):
    """iOS / Pythonista 平台专用命令集合"""

    def __init__(self, socket):
        super().__init__(socket)
        self._ios_platform_service = iOSPlatformService(self)

    # ------------------ 基础 shell ------------------ #

    @desc('List directory contents', group='shell')
    def ls(self, path='.'):
        return self._ios_platform_service.list_directory(path)

    @desc('Show current username', group='shell')
    def whoami(self):
        return self._ios_platform_service.get_username()

    @desc('Create empty file', group='shell')
    def touch(self, path):
        return self._ios_platform_service.touch(path)

    @desc('Create directory', group='shell')
    def mkdir(self, path):
        return self._ios_platform_service.mkdir(path)

    @desc('Remove file', group='shell')
    def rm(self, path):
        return self._ios_platform_service.rm(path)

    @desc('Remove directory recursively', group='shell')
    def rmdir(self, path):
        return self._ios_platform_service.rmdir(path)

    @desc('Read text file', group='shell')
    def cat(self, path):
        return self._ios_platform_service.cat(path)

    @desc('Compute file MD5', group='shell')
    def md5sum(self, path=''):
        return self._ios_platform_service.md5sum(path)

    @desc('Print environment variables', group='shell')
    def printenv(self, name=''):
        return self._ios_platform_service.printenv(name)

    @desc('Echo text or expand environment variables', group='shell')
    def echo(self, text=''):
        return self._ios_platform_service.echo(text)

    # ------------------ 系统信息 ------------------ #

    @desc('Get system information', group='platform')
    @timeout(20)
    def getinfo(self):
        return self._ios_platform_service.collect_info()

    # ------------------ 剪贴板 ------------------ #

    @desc('Read clipboard text', group='mobile')
    def readclip(self):
        return self._ios_platform_service.read_clipboard()

    @desc('Write clipboard text', group='mobile')
    def writeclip(self, text=''):
        return self._ios_platform_service.write_clipboard(text)

    # ------------------ 手机常用 ------------------ #

    @desc('Open URL', group='console')
    def openurl(self, url):
        return self._ios_platform_service.open_url(url)

    @desc('Clear console output', group='console')
    def clearconsole(self):
        return self._ios_platform_service.clear_console()

    @desc('QuickLook preview file', group='console')
    def quicklook(self, path):
        return self._ios_platform_service.quick_look(path)

    @desc('Open file in other app', group='console')
    def openin(self, path):
        return self._ios_platform_service.open_in(path)

    @desc('Get current location', group='mobile')
    @timeout(15)
    def getlocation(self):
        return self._ios_platform_service.get_location()

    @desc('Speak text', group='mobile')
    def speak(self, text=''):
        return self._ios_platform_service.speak(text)

    @desc('List contacts via CNContactStore', group='mobile')
    def listcontacts(self):
        return self._ios_platform_service.list_contacts()

    @desc('Pick photo or file and upload', group='console')
    @interruptible()
    def pickupload(self, kind='photo'):
        return self._ios_platform_service.pick_upload(kind)

    @desc('Keep screen awake', group='console')
    def keepawake(self, arg):
        return self._ios_platform_service.keepawake(arg)

    @desc('Force quit app', group='console')
    def killapp(self):
        return self._ios_platform_service.killapp()

    @argument_command('alert', spec=ALERT_ARGUMENT_SPEC)
    def alert(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_alert(args_dict)

    @argument_command('notify', spec=NOTIFY_ARGUMENT_SPEC)
    def notify(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_notify(args_dict)

    @argument_command('find', spec=FIND_ARGUMENT_SPEC)
    def find(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_find(args_dict)

    @argument_command('tree', spec=TREE_ARGUMENT_SPEC)
    def tree(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_tree(args_dict)

    @argument_command('head', spec=HEAD_ARGUMENT_SPEC)
    @interruptible()
    def head(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_head(args_dict)

    @argument_command('tail', spec=TAIL_ARGUMENT_SPEC)
    @interruptible()
    def tail(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_tail(args_dict)

    @argument_command('wget', spec=WGET_ARGUMENT_SPEC)
    @interruptible()
    def wget(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_wget(args_dict)

    @argument_command('tcp_ping', spec=TCP_PING_ARGUMENT_SPEC)
    @interruptible()
    def tcp_ping(self, args_dict, payload=None):
        return self._ios_platform_service.acmd_tcp_ping(args_dict)
