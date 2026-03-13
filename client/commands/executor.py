import inspect
import platform

from core.utils.common_util import parse


class CommandExecutor:
    PLATFORM_COMMAND_MODULES = {
        'windows': ('client.commands.platform.win', 'WindowsCommands'),
        'darwin': ('client.commands.platform.mac', 'MacCommands'),
        'linux': ('client.commands.platform.linux', 'LinuxCommands'),
    }

    def __init__(self, socket):
        self.socket = socket
        self.platform_commands = None

    def _get_platform_name(self) -> str:
        """
        获取当前系统平台名称
        """
        return platform.system().lower()

    def _load_platform_command_class(self):
        """
        根据当前平台动态加载命令类
        """
        system = self._get_platform_name()
        platform_info = self.PLATFORM_COMMAND_MODULES.get(system)
        if not platform_info:
            raise NotImplementedError(f"Unsupported OS: {system}")

        module_name, class_name = platform_info
        module = __import__(module_name, fromlist=[class_name])
        return getattr(module, class_name)

    def get_commands(self):
        """
        获取当前平台对应的命令实例（懒加载）
        """
        if self.platform_commands is None:
            command_class = self._load_platform_command_class()
            self.platform_commands = command_class(self.socket)
        return self.platform_commands

    def _resolve_command_method(self, commands, name):
        """
        获取命令方法；如果方法不存在或不是受支持命令，则返回 None
        """
        if not hasattr(commands, name):
            return None

        func = getattr(commands, name)
        if not hasattr(func, 'help'):
            return None

        return func

    def _execute_method(self, func, arg):
        """
        执行命令方法
        """
        if len(inspect.signature(func).parameters):
            return func(arg)
        return func()

    def _execute_shell_fallback(self, commands, raw_command):
        """
        当命令无法匹配到受支持方法时，回退到 shell 执行
        """
        return commands.shell(raw_command)

    def execute_command(self, command_id, command):
        """
        执行命令
        :param command_id: 命令id，用于返回结果时指定对应的命令id
        :param command: 命令字符串
        :return: 执行结果元组（状态和消息）
        """
        name, arg = parse(command)
        commands = self.get_commands()
        commands.command_id = command_id

        func = self._resolve_command_method(commands, name)
        if func is None:
            return self._execute_shell_fallback(commands, command)

        return self._execute_method(func, arg)


# import inspect
#
# import platform
# from core.utils.common_util import parse
#
#
# class CommandExecutor:
#     def __init__(self, socket):
#         self.socket = socket
#         self.platform_commands = None
#
#     def get_commands(self):
#         if not self.platform_commands:
#             system = platform.system().lower()
#             if system == 'windows':
#                 from client.commands.platform.win import WindowsCommands
#                 self.platform_commands = WindowsCommands(self.socket)
#                 return self.platform_commands
#             elif system == 'darwin':
#                 from client.commands.platform.mac import MacCommands
#                 self.platform_commands = MacCommands(self.socket)
#                 return self.platform_commands
#             elif system == 'linux':
#                 from client.commands.platform.linux import LinuxCommands
#                 self.platform_commands = LinuxCommands(self.socket)
#                 return self.platform_commands
#             else:
#                 raise NotImplementedError(f"Unsupported OS: {system}")
#         return self.platform_commands
#
#     def execute_command(self, command_id, command):
#         """
#         执行命令
#         :param command_id: 命令id，用于set到该实例中，返回结果时指定对应的命令id
#         :param command: 命令字符串
#         :return: 执行结果元组（状态和消息）
#         """
#
#         name, arg = parse(command)
#         commands = self.get_commands()
#         commands.command_id = command_id
#         # 检查实例是否有一个与解析出的函数名相对应的方法
#         if hasattr(commands, name):
#             # 使用函数名获取方法对象
#             func = getattr(commands, name)
#             # 检查方法是否有 'desc' 注解
#             if hasattr(func, 'help'):
#                 # 如果方法接受参数，则带上提供的参数调用它
#                 if len(inspect.signature(func).parameters):
#                     return func(arg)
#                 # 如果方法不接受参数，则无参数调用
#                 return func()
#             else:
#                 # 如果方法没有 'desc' 注解，则执行 'shell' 方法并将原始命令作为参数
#                 return commands.shell(command)
#         else:
#             # 如果不存在与解析出的名字相对应的方法，则执行 'shell' 方法并将原始命令作为参数
#             return commands.shell(command)
