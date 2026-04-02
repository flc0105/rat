from functools import partial

from core.utils.parsing import parse
from server.application.command.builtin_command_handler import BuiltinCommandHandler
from server.application.command.command_plan_builder import CommandPlanBuilder
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

    def _resolve_alias_command(self, name, arg):
        try:
            plan = self.plan_builder.build_alias_plan(name, arg)
            if not plan:
                return None
            return self._execute_remote_plan(plan)
        except Exception as e:
            return partial(self._yield_error, e)

    def _resolve_default_command(self, raw_command):
        plan = self.plan_builder.build_default_plan(raw_command)
        return self._execute_remote_plan(plan)

    def _resolve_argument_command(self, raw_command):
        plan = self.plan_builder.build_argument_command_plan(raw_command)
        return self._execute_remote_plan(plan)

    def process_command(self, cmd, history_entry_id: str = ''):
        self.current_history_entry_id = (history_entry_id or '').strip()
        name, arg = parse(cmd)

        if self.plan_builder.is_argument_command(cmd):
            return self._resolve_argument_command(cmd)

        builtin_handler = self._resolve_builtin_command(name, arg)
        if builtin_handler:
            return builtin_handler

        alias_handler = self._resolve_alias_command(name, arg)
        if alias_handler:
            return alias_handler

        return self._resolve_default_command(cmd)