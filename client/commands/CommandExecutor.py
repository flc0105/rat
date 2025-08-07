import inspect

from client.commands.CommandBase import *
from common.util import parse


class CommandExecutor:
    def __init__(self, socket):
        self.socket = socket
        self.platform_commands = None

    def get_commands(self):
        if not self.platform_commands:
            system = platform.system().lower()
            if system == 'windows':
                from client.commands.WindowsCommands import WindowsCommands  # ⚠️ 动态导入
                self.platform_commands = WindowsCommands(self.socket)
                return self.platform_commands
            elif system == 'darwin':
                from client.commands.MacCommands import MacCommands
                self.platform_commands = MacCommands(self.socket)
                return self.platform_commands
            elif system == 'linux':
                from client.commands.LinuxCommands import LinuxCommands
                self.platform_commands = LinuxCommands(self.socket)
                return self.platform_commands
            else:
                raise NotImplementedError(f"Unsupported OS: {system}")
        return self.platform_commands

    def execute_command(self, command_id, command):
        """
        执行命令
        :param command_id: 命令id，用于set到该实例中，返回结果时指定对应的命令id
        :param command: 命令字符串
        :return: 执行结果元组（状态和消息）
        """
        # 将 command_id 设置为实例变量
        # self.command_id = command_id
        # 解析 command 得到函数名和其参数（如果有）
        name, arg = parse(command)
        commands = self.get_commands()
        commands.command_id = command_id
        # 检查实例是否有一个与解析出的函数名相对应的方法
        if hasattr(commands, name):
            # 使用函数名获取方法对象
            func = getattr(commands, name)
            # 检查方法是否有 'desc' 注解
            if hasattr(func, 'help'):
                # 如果方法接受参数，则带上提供的参数调用它
                if len(inspect.signature(func).parameters):
                    return func(arg)
                # 如果方法不接受参数，则无参数调用
                return func()
            else:
                # 如果方法没有 'desc' 注解，则执行 'shell' 方法并将原始命令作为参数
                return commands.shell(command)
        else:
            # 如果不存在与解析出的名字相对应的方法，则执行 'shell' 方法并将原始命令作为参数
            return commands.shell(command)
