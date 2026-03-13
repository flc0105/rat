import inspect
import platform

from core.utils.parsing import parse


class CommandExecutor:
    PLATFORM_COMMAND_MODULES = {
        'windows': ('client.commands.platform.win', 'WindowsCommands'),
        'darwin': ('client.commands.platform.mac', 'MacCommands'),
        'linux': ('client.commands.platform.linux', 'LinuxCommands'),
    }

    def __init__(self, socket):
        self.socket = socket
        self.platform_commands = None

    # ------------------ 平台命令加载 ------------------ #
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

    # ------------------ 命令路由 ------------------ #
    def _resolve_builtin_command(self, commands, name):
        """
        解析平台内置命令方法；如果不存在或不是导出命令，则返回 None
        """
        if not hasattr(commands, name):
            return None

        func = getattr(commands, name)
        if not hasattr(func, 'help'):
            return None

        return func

    def _resolve_default_command(self, commands, raw_command):
        """
        默认回退到 shell 执行
        """
        return lambda: commands.shell(raw_command)

    def _invoke_command_method(self, func, arg):
        """
        调用命令方法
        """
        if len(inspect.signature(func).parameters):
            return func(arg)
        return func()

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

        builtin_command = self._resolve_builtin_command(commands, name)
        if builtin_command:
            return self._invoke_command_method(builtin_command, arg)

        default_command = self._resolve_default_command(commands, command)
        return default_command()