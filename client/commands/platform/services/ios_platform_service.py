from client.commands.platform.services.ios.console_service import iOSConsoleService
from client.commands.platform.services.ios.file_system_service import iOSFileSystemService
from client.commands.platform.services.ios.network_service import iOSNetworkService
from client.commands.platform.services.ios.system_service import iOSSystemService


class iOSPlatformService:
    """
    iOS / Pythonista 平台能力 facade。

    这里只负责组合平台子服务，具体实现放到 services/ios/*。
    """

    def __init__(self, owner):
        self.owner = owner
        self.file_system = iOSFileSystemService(owner)
        self.system = iOSSystemService(owner)
        self.console = iOSConsoleService(owner)
        self.network = iOSNetworkService(owner)

    # ------------------ 基础 shell ------------------ #
    def list_directory(self, path):
        return self.file_system.list_directory(path)

    def get_username(self):
        return self.system.get_username()

    def touch(self, path):
        return self.file_system.touch(path)

    def mkdir(self, path):
        return self.file_system.mkdir(path)

    def rm(self, path):
        return self.file_system.rm(path)

    def rmdir(self, path):
        return self.file_system.rmdir(path)

    def cat(self, path):
        return self.file_system.cat(path)

    def md5sum(self, path):
        return self.file_system.md5sum(path)

    def printenv(self, name):
        return self.file_system.printenv(name)

    def echo(self, text):
        return self.file_system.echo(text)

    # ------------------ 系统信息 ------------------ #
    def collect_info(self):
        return self.system.collect_info()

    def list_contacts(self):
        return self.system.list_contacts()

    # ------------------ 剪贴板 / 控制台 / 移动端能力 ------------------ #
    def read_clipboard(self):
        return self.console.read_clipboard()

    def write_clipboard(self, text):
        return self.console.write_clipboard(text)

    def open_url(self, url):
        return self.console.open_url(url)

    def clear_console(self):
        return self.console.clear_console()

    def quick_look(self, path):
        return self.console.quick_look(path)

    def open_in(self, path):
        return self.console.open_in(path)

    def get_location(self):
        return self.console.get_location()

    def speak(self, text):
        return self.console.speak(text)

    def pick_upload(self, kind):
        return self.console.pick_upload(kind)

    def keepawake(self, arg):
        return self.console.keepawake(arg)

    def killapp(self):
        return self.console.killapp()

    # ------------------ acmd 平台扩展 ------------------ #
    def acmd_alert(self, args_dict):
        return self.console.acmd_alert(args_dict)

    def acmd_notify(self, args_dict):
        return self.console.acmd_notify(args_dict)

    def acmd_find(self, args_dict):
        return self.file_system.acmd_find(args_dict)

    def acmd_tree(self, args_dict):
        return self.file_system.acmd_tree(args_dict)

    def acmd_head(self, args_dict):
        return self.file_system.acmd_head(args_dict)

    def acmd_tail(self, args_dict):
        return self.file_system.acmd_tail(args_dict)

    def acmd_wget(self, args_dict):
        return self.file_system.acmd_wget(args_dict)

    def tcp_ping(self, host, port=80, count=4, timeout=2.0):
        return self.network.tcp_ping(host, port=port, count=count, timeout=timeout)

    def acmd_tcp_ping(self, args_dict):
        return self.network.acmd_tcp_ping(args_dict)