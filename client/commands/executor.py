import inspect
import platform

from client.commands.argument_command_registry import ArgumentCommandRegistry
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
        self.argument_command_registry = None

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

    def _prepare_commands(self, command_id):
        """
        获取命令实例并绑定当前 command_id
        """
        commands = self.get_commands()
        commands.command_id = command_id
        return commands

    def get_argument_command_registry(self):
        """
        获取当前平台对应的 acmd 注册表（懒加载）
        """
        if self.argument_command_registry is None:
            self.argument_command_registry = ArgumentCommandRegistry(self.get_commands())
        return self.argument_command_registry

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
        commands = self._prepare_commands(command_id)

        builtin_command = self._resolve_builtin_command(commands, name)
        if builtin_command:
            return self._invoke_command_method(builtin_command, arg)

        default_command = self._resolve_default_command(commands, command)
        return default_command()

    def execute_argument_command(self, command_id, payload: dict):
        """
        执行 acmd 结构化实验命令
        :param command_id: 命令id
        :param payload: 结构化命令负载
        :return: 执行结果元组（状态和消息）
        """
        self._prepare_commands(command_id)
        registry = self.get_argument_command_registry()
        return registry.execute(payload)

    def execute_script_command(self, command_id, script_text: str, kwargs=None):
        """
        执行 script 消息
        统一通过 CommandExecutor 入口分发，避免绕过命令执行器
        """
        commands = self._prepare_commands(command_id)
        return commands.pyexec(script_text, kwargs=kwargs)