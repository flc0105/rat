from functools import partial
import re

from core.utils.parsing import parse
from server.application.command.builtin_command_handler import BuiltinCommandHandler
from server.application.command.command_plan_builder import CommandPlanBuilder
from server.application.command.command_router import CommandRouter
from server.application.execution.remote_execution_service import RemoteExecutionService


class CommandExecutor:
    def __init__(
        self,
        conn,
        server,
        remote_execution_service=None,
        plan_builder=None,
        use_foreground_guard: bool = False,
        foreground_source: str = 'cli'
    ):
        self.conn = conn
        self.server = server
        self.current_history_entry_id = ''
        self.remote_execution_service = remote_execution_service or RemoteExecutionService(server)
        self.plan_builder = plan_builder or CommandPlanBuilder(server.alias_manager)
        self.use_foreground_guard = bool(use_foreground_guard)
        self.foreground_source = (foreground_source or '').strip() or 'cli'

        self.builtin_handler = BuiltinCommandHandler(
            conn=self.conn,
            server=self.server,
            plan_builder=self.plan_builder,
            remote_execution_service=self.remote_execution_service,
            history_entry_id_provider=self._get_current_history_entry_id,
            plan_executor_factory=self._create_plan_executor,
        )
        self.command_router = CommandRouter(
            plan_builder=self.plan_builder,
            plan_executor=self._execute_remote_plan,
            error_executor=self._yield_error,
        )

    def _get_current_history_entry_id(self) -> str:
        return self.current_history_entry_id

    def _yield_error(self, error):
        yield 0, str(error)

    def _create_plan_executor(self):
        return self._execute_remote_plan

    def _execute_remote_plan(self, plan: dict):
        if self.use_foreground_guard:
            return partial(
                self.remote_execution_service.stream_foreground_command,
                self.conn,
                plan.get('command', ''),
                command_type=plan.get('command_type', 'command'),
                extra=plan.get('extra'),
                history_entry_id=self.current_history_entry_id,
                task_type='command',
                source=self.foreground_source,
            )

        return partial(
            self.remote_execution_service.stream_command,
            self.conn,
            plan.get('command', ''),
            command_type=plan.get('command_type', 'command'),
            extra=plan.get('extra'),
            history_entry_id=self.current_history_entry_id
        )

    def get_command_candidates(self):
        return self.builtin_handler.get_command_candidates()

    def _resolve_builtin_command(self, name, arg):
        try:
            builtin_iter = self.builtin_handler.resolve_builtin_command(name, arg)
            if builtin_iter is None:
                return None
            return partial(lambda it: it, builtin_iter)
        except Exception as e:
            return partial(self._yield_error, e)

    def _resolve_history_quick_command(self, cmd: str) -> str:
        """
        解析 !<history index> 快捷历史命令。

        规则：
        - 仅匹配 !+数字，例如 !1 / !12
        - 序号直接复用 quick history 当前 index
        - quick history 已经受 pin 状态影响，因此这里直接读取当前 quick history 视图
        """
        command_text = (cmd or '').strip()
        matched = re.fullmatch(r'!(\d+)', command_text)
        if matched is None:
            return command_text

        history_index = int(matched.group(1))
        history_items = self.server.command_history.get_history_for_connection(self.conn)

        for item in history_items:
            try:
                current_index = int(item.get('index', 0) or 0)
            except Exception:
                current_index = 0

            if current_index != history_index:
                continue

            resolved_command = str(item.get('command') or '').strip()
            if resolved_command:
                return resolved_command
            break

        raise ValueError(f'History index not found: {history_index}')

    def _sync_history_entry_command(self, resolved_command: str):
        """
        将已创建的 history entry 从原始输入同步为展开后的真实命令。

        这样可以保持：
        - 历史记录尽量落原始命令，而不是 !数字
        - quick history 去重 / pin 继承继续基于真实命令生效
        """
        entry_id = (self.current_history_entry_id or '').strip()
        if not entry_id:
            return

        self.server.command_history.update_entry_command_for_connection(
            self.conn,
            entry_id,
            resolved_command,
        )

    def _prepare_command(self, cmd: str):
        """
        预处理输入命令。

        返回：
        - resolved_command: 真正参与后续路由与执行的命令
        - display_message: 如果发生 quick history 展开，则返回一条前置提示，供上层 yield
        """
        command_text = (cmd or '').strip()
        resolved_command = self._resolve_history_quick_command(command_text)

        if resolved_command != command_text:
            self._sync_history_entry_command(resolved_command)
            return resolved_command, f'sending command: {resolved_command}'

        return resolved_command, ''

    def _wrap_with_prefix_message(self, executor, display_message: str):
        """
        在真实执行输出前，先 yield 一条提示消息。
        """
        if not display_message:
            return executor

        def wrapped():
            yield 1, display_message
            for item in executor():
                yield item

        return wrapped

    def process_command(self, cmd, history_entry_id: str = ''):
        self.current_history_entry_id = (history_entry_id or '').strip()

        resolved_command, display_message = self._prepare_command(cmd)
        name, arg = parse(resolved_command)

        builtin_handler = self._resolve_builtin_command(name, arg)
        if builtin_handler:
            return self._wrap_with_prefix_message(builtin_handler, display_message)

        resolved_executor = self.command_router.resolve(resolved_command, name, arg)
        return self._wrap_with_prefix_message(resolved_executor, display_message)