import logging

from server.application.command.command_execution_event import CommandExecutionEvent
from server.application.execution.execution_context import ExecutionContext


class CommandExecutionPipeline:
    """
    统一命令执行编排入口。

    职责：
    - 创建执行历史
    - 调用 command executor
    - 产出标准化执行事件
    - 统一 finalize history
    """

    def __init__(self, command_history_orchestrator, output_writer=None, error_logger=None):
        self.command_history_orchestrator = command_history_orchestrator
        self.output_writer = output_writer or (lambda *_: None)
        self.error_logger = error_logger or logging.getLogger(__name__)

    def _resolve_cwd_end(self, cwd_end_provider=None) -> str:
        cwd_end = ''
        if callable(cwd_end_provider):
            cwd_end = cwd_end_provider() or ''
        return cwd_end

    def _finalize_history(self, context: ExecutionContext, final_ok: bool, cwd_end_provider=None):
        if not context.history_entry_id:
            return

        self.command_history_orchestrator.finalize_execution(
            context.session,
            context.history_entry_id,
            final_ok,
            cwd_end=self._resolve_cwd_end(cwd_end_provider),
        )

    def _build_output_event(self, status: int, result) -> CommandExecutionEvent:
        text = '' if result is None else str(result)
        normalized_text = text.strip().lower()

        if normalized_text == 'cancelled' or 'command cancelled' in normalized_text:
            return CommandExecutionEvent.cancelled(text or 'cancelled')

        if int(status or 0) == 0:
            return CommandExecutionEvent.error(text)

        return CommandExecutionEvent.chunk(int(status), text)

    def iter_events(
        self,
        context: ExecutionContext,
        command_executor,
        *,
        cwd_end_provider=None,
        finalize_history: bool = True,
        swallow_exception: bool = False,
    ):
        final_ok = True
        cancelled = False

        yield CommandExecutionEvent.started(
            context.command,
            payload={
                'source': context.source,
                'task_id': context.task_id,
                'history_entry_id': context.history_entry_id,
            },
        )

        try:
            func = command_executor.process_command(
                context.command,
                history_entry_id=context.history_entry_id,
            )
            if func:
                for item in func():
                    status = item[0]
                    result = item[1] if len(item) > 1 else ''
                    event = self._build_output_event(status, result)

                    if event.event_type == CommandExecutionEvent.ERROR:
                        final_ok = False
                    elif event.event_type == CommandExecutionEvent.CANCELLED:
                        cancelled = True
                        final_ok = False

                    yield event

        except Exception as exc:
            final_ok = False
            self.error_logger.exception(
                'CommandExecutionPipeline failed: command=%r source=%s task_id=%s history_entry_id=%s',
                context.command,
                context.source,
                context.task_id,
                context.history_entry_id,
            )
            if swallow_exception:
                yield CommandExecutionEvent.error(str(exc))
            else:
                raise

        finally:
            if finalize_history:
                self._finalize_history(
                    context,
                    final_ok and not cancelled,
                    cwd_end_provider=cwd_end_provider,
                )

        if cancelled:
            yield CommandExecutionEvent.cancelled('cancelled', payload={'terminal': True})
        else:
            yield CommandExecutionEvent.completed(final_ok)

    def _emit_legacy_output(self, event: CommandExecutionEvent, writer):
        if event.event_type == CommandExecutionEvent.CHUNK:
            writer(event.status, event.text)
        elif event.event_type == CommandExecutionEvent.ERROR:
            writer(0, event.text)
        elif event.event_type == CommandExecutionEvent.CANCELLED and not event.payload.get('terminal'):
            writer(0, event.text or 'cancelled')

    def execute_bound(
        self,
        session,
        command_executor,
        cmd: str,
        *,
        history_entry_id: str = '',
        output_writer=None,
        cwd_end_provider=None,
        finalize_history: bool = True,
        swallow_exception: bool = False,
        source: str = 'cli',
        task_type: str = 'command',
        task_id: str = '',
        tab_id: str = '',
        metadata: dict | None = None,
    ) -> bool:
        writer = output_writer or self.output_writer
        context = ExecutionContext.from_session(
            session,
            cmd,
            source=source,
            task_type=task_type,
            task_id=task_id,
            history_entry_id=history_entry_id,
            tab_id=tab_id,
            metadata=metadata,
        )
        final_ok = True

        for event in self.iter_events(
            context,
            command_executor,
            cwd_end_provider=cwd_end_provider,
            finalize_history=finalize_history,
            swallow_exception=swallow_exception,
        ):
            if event.event_type == CommandExecutionEvent.COMPLETED:
                final_ok = bool(event.ok)
                continue

            if event.event_type == CommandExecutionEvent.CANCELLED and event.payload.get('terminal'):
                final_ok = False
                continue

            self._emit_legacy_output(event, writer)

        return final_ok

    def execute(
        self,
        session,
        command_executor,
        cmd: str,
        *,
        source: str = 'cli',
        cwd_end_provider=None,
    ) -> bool:
        entry_id = self.command_history_orchestrator.begin_execution(
            session,
            cmd,
            source=source,
        )

        return self.execute_bound(
            session,
            command_executor,
            cmd,
            history_entry_id=entry_id,
            cwd_end_provider=cwd_end_provider,
            finalize_history=True,
            swallow_exception=False,
            source=source,
        )