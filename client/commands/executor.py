import inspect
import platform
import threading

from client.commands.argument_command_registry import ArgumentCommandRegistry
from client.commands.command_context import CommandExecutionContext
from core.utils.parsing import parse
from client.config.runtime_config import COMMAND_DEFAULT_TIMEOUT


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

        self._execution_contexts = {}
        self._context_lock = threading.RLock()

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

    def _normalize_timeout(self, timeout):
        if timeout in (None, ''):
            return None

        try:
            value = float(timeout)
        except Exception:
            return None

        if value <= 0:
            return None
        return value

    def _extract_timeout(self, options=None):
        if not isinstance(options, dict):
            return None

        return self._normalize_timeout(
            options.get('_timeout', options.get('timeout', COMMAND_DEFAULT_TIMEOUT))
        )

    def _get_or_create_execution_context(self, command_id, timeout=None):
        normalized_timeout = self._normalize_timeout(timeout)

        with self._context_lock:
            context = self._execution_contexts.get(command_id)
            if context is None:
                context = CommandExecutionContext(command_id, timeout=normalized_timeout)
                self._execution_contexts[command_id] = context
            elif normalized_timeout is not None:
                context.set_timeout(normalized_timeout)
            return context

    def _clear_execution_context(self, command_id):
        with self._context_lock:
            context = self._execution_contexts.pop(command_id, None)

        if context is not None:
            try:
                context.run_cleanup()
            except Exception:
                pass

    def cancel_command(self, command_id: int) -> dict:
        """
        请求取消指定命令
        """
        with self._context_lock:
            context = self._execution_contexts.get(command_id)

        if context is None:
            return {
                'accepted': False,
                'message': 'Command is not running',
            }

        return context.request_cancel()

    def _prepare_commands(self, command_id, timeout=None):
        """
        获取命令实例并绑定当前 command_id
        """
        commands = self.get_commands()
        execution_context = self._get_or_create_execution_context(command_id, timeout=timeout)
        if hasattr(commands, 'bind_execution'):
            commands.bind_execution(command_id, execution_context)
        else:
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

    def _execute_with_cleanup(self, command_id, invoke):
        try:
            return invoke()
        finally:
            self._clear_execution_context(command_id)

    def execute_command(self, command_id, command, options=None):
        """
        执行命令
        :param command_id: 命令id，用于返回结果时指定对应的命令id
        :param command: 命令字符串
        :param options: 执行选项（如 timeout）
        :return: 执行结果元组（状态和消息）
        """
        def _invoke():
            name, arg = parse(command)
            commands = self._prepare_commands(
                command_id,
                timeout=self._extract_timeout(options)
            )

            builtin_command = self._resolve_builtin_command(commands, name)
            if builtin_command:
                return self._invoke_command_method(builtin_command, arg)

            default_command = self._resolve_default_command(commands, command)
            return default_command()

        return self._execute_with_cleanup(command_id, _invoke)

    def execute_argument_command(self, command_id, payload: dict, options=None):
        """
        执行 acmd 结构化实验命令
        :param command_id: 命令id
        :param payload: 结构化命令负载
        :param options: 执行选项（如 timeout）
        :return: 执行结果元组（状态和消息）
        """
        def _invoke():
            payload_timeout = self._extract_timeout(payload)
            commands = self._prepare_commands(
                command_id,
                timeout=payload_timeout if payload_timeout is not None else self._extract_timeout(options)
            )
            registry = self.get_argument_command_registry()
            return registry.execute(payload)

        return self._execute_with_cleanup(command_id, _invoke)

    def execute_script_command(self, command_id, script_text: str, kwargs=None, options=None):
        """
        执行 script 消息
        统一通过 CommandExecutor 入口分发，避免绕过命令执行器
        """
        def _invoke():
            timeout = self._extract_timeout(options)
            if timeout is None and isinstance(kwargs, dict):
                timeout = self._extract_timeout(kwargs)

            commands = self._prepare_commands(command_id, timeout=timeout)
            return commands.pyexec(script_text, kwargs=kwargs)

        return self._execute_with_cleanup(command_id, _invoke)
