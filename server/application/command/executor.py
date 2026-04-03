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
            command_processor_factory=self._create_nested_command_processor,
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

    def _create_nested_command_processor(self):
        def processor(cmd: str):
            return self.process_command(cmd, history_entry_id=self.current_history_entry_id)
        return processor

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

    def _rewrite_history_shortcut(self, cmd: str) -> str:
        """
        将 !<index> 改写为正式 builtin: history run <index>

        这里故意只保留很薄的一层语法糖，不在 executor 里做真正的历史解析。
        真正的 quick history 查找、提示输出、以及继续执行，统一交给 history builtin。
        """
        command_text = (cmd or '').strip()
        matched = re.fullmatch(r'!(\d+)', command_text)
        if matched is None:
            return command_text

        history_index = matched.group(1)
        return f'history run {history_index}'

    def _resolve_alias_preview_command(self, cmd: str) -> str:
        """
        为 alias 命令做一层发送前预览。

        这里只用于展示 sending command: xxx，
        不在这里真正执行 alias 展开，真正路由仍然交给原有 command router / plan builder。
        """
        command_text = (cmd or '').strip()
        if not command_text:
            return ''

        name, arg = parse(command_text)
        alias_map = self.server.alias_manager.list_aliases() or {}
        mapped_command = str(alias_map.get(name) or '').strip()

        if not mapped_command:
            return ''

        if arg:
            return f'{mapped_command} {arg}'.strip()

        return mapped_command

    def _wrap_with_prefix_message(self, executor, display_message: str):
        if not display_message:
            return executor

        def wrapped():
            yield 1, display_message
            for item in executor():
                yield item

        return wrapped

    def process_command(self, cmd, history_entry_id: str = ''):
        self.current_history_entry_id = (history_entry_id or '').strip()

        normalized_command = self._rewrite_history_shortcut(cmd)
        alias_preview_command = self._resolve_alias_preview_command(normalized_command)
        display_message = f'sending command: {alias_preview_command}' if alias_preview_command else ''

        name, arg = parse(normalized_command)

        builtin_handler = self._resolve_builtin_command(name, arg)
        if builtin_handler:
            return self._wrap_with_prefix_message(builtin_handler, display_message)

        resolved_executor = self.command_router.resolve(normalized_command, name, arg)
        return self._wrap_with_prefix_message(resolved_executor, display_message)