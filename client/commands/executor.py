import inspect
from dataclasses import dataclass
from typing import Any, Callable

from client.commands.services.command.command_catalog import CommandCatalog
from client.commands.services.command.command_context_store import CommandExecutionContextStore
from core.utils.command_output import render_structured_result
from core.utils.parsing import parse


@dataclass
class CommandExecutionRequest:
    """
    统一命令执行请求。

    说明：
    - 这里只承载 CommandExecutor 主链分发所需的最小字段
    - 不引入额外兼容入口，统一 command / acmd / script 三类请求的绑定流程
    """

    command_id: int
    timeout: float | None = None


class CommandExecutor:
    """
    命令执行器。

    当前职责收口为：
    - 使用 CommandCatalog 获取平台命令对象 / acmd registry
    - 使用 CommandExecutionContextStore 管理单次命令生命周期
    - 只保留命令路由与调用编排
    """

    def __init__(self, socket):
        self.socket = socket
        self.catalog = CommandCatalog(socket)
        self.context_store = CommandExecutionContextStore()

    def get_commands(self):
        """
        获取当前平台对应的命令实例（懒加载）
        """
        commands = self.catalog.get_commands()
        if hasattr(commands, 'set_command_runtime'):
            commands.set_command_runtime(self)
        return commands

    def get_argument_command_registry(self):
        """
        获取当前平台对应的 acmd 注册表（懒加载）
        """
        return self.catalog.get_argument_command_registry()

    def _extract_timeout(self, options=None):
        return self.context_store.extract_timeout(options)

    def _build_request(self, command_id, options=None, payload_options=None) -> CommandExecutionRequest:
        timeout = self._extract_timeout(payload_options)
        if timeout is None:
            timeout = self._extract_timeout(options)
        return CommandExecutionRequest(command_id=command_id, timeout=timeout)

    def _get_or_create_execution_context(self, command_id, timeout=None):
        return self.context_store.get_or_create(command_id, timeout=timeout)

    def _clear_execution_context(self, command_id):
        self.context_store.clear(command_id)

    def cancel_command(self, command_id: int) -> dict:
        """
        请求取消指定命令
        """
        return self.context_store.cancel(command_id)

    def _bind_execution(self, commands, request: CommandExecutionRequest):
        """
        绑定命令实例与当前执行上下文。
        """
        execution_context = self._get_or_create_execution_context(
            request.command_id,
            timeout=request.timeout,
        )
        if hasattr(commands, 'bind_execution'):
            commands.bind_execution(request.command_id, execution_context)
        else:
            commands.command_id = request.command_id
        return commands

    def _prepare_commands(self, request: CommandExecutionRequest):
        """
        获取命令实例并绑定当前 command_id
        """
        commands = self.get_commands()
        return self._bind_execution(commands, request)

    def _render_command_result(self, result, output_format='text'):
        return render_structured_result(result, output_format=output_format)

    def _resolve_builtin_output_format(self, arg: Any) -> str:
        return 'json' if str(arg or '').strip().lower() in ('json', '--json') else 'text'

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

    def _execute_with_cleanup(self, command_id, invoke: Callable[[], Any]):
        try:
            return invoke()
        finally:
            self._clear_execution_context(command_id)

    def _execute_bound_request(self, request: CommandExecutionRequest, invoke: Callable[[Any], Any]):
        def _runner():
            commands = self._prepare_commands(request)
            return invoke(commands)

        return self._execute_with_cleanup(request.command_id, _runner)

    def execute_command(self, command_id, command, options=None):
        """
        执行命令
        :param command_id: 命令id，用于返回结果时指定对应的命令id
        :param command: 命令字符串
        :param options: 执行选项（如 timeout）
        :return: 执行结果元组（状态和消息）
        """
        request = self._build_request(command_id, options=options)

        def _invoke(commands):
            name, arg = parse(command)

            builtin_command = self._resolve_builtin_command(commands, name)
            if builtin_command:
                result = self._invoke_command_method(builtin_command, arg)
                return self._render_command_result(
                    result,
                    output_format=self._resolve_builtin_output_format(arg),
                )

            default_command = self._resolve_default_command(commands, command)
            return default_command()

        return self._execute_bound_request(request, _invoke)

    def execute_argument_command(self, command_id, payload: dict, options=None):
        """
        执行 acmd 结构化实验命令
        :param command_id: 命令id
        :param payload: 结构化命令负载
        :param options: 执行选项（如 timeout）
        :return: 执行结果元组（状态和消息）
        """
        request = self._build_request(command_id, options=options, payload_options=payload)

        def _invoke(_commands):
            registry = self.get_argument_command_registry()
            return registry.execute(payload)

        return self._execute_bound_request(request, _invoke)

    def execute_script_command(self, command_id, script_text: str, kwargs=None, options=None):
        """
        执行 script 消息
        统一通过 CommandExecutor 入口分发，避免绕过命令执行器

        当前约定：
        - script 默认只走 stream 语义
        - 当前进程 / 子进程由 Python execution strategy 决定
        """
        request = self._build_request(command_id, options=options, payload_options=kwargs)

        def _invoke(commands):
            return commands.execute_script_stream(script_text, kwargs=kwargs)

        return self._execute_bound_request(request, _invoke)