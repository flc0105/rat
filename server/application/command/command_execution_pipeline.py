from server.connection.client_session import ClientSession


class CommandExecutionPipeline:
    """
    统一命令执行编排入口。

    职责：
    - 创建执行历史
    - 调用 command executor
    - 消费输出
    - 统一 finalize

    说明：
    - 不负责命令规划细节
    - 不负责 builtin/alias/acmd 的具体解析
    - 这里只做“执行生命周期编排”
    """

    def __init__(self, command_history_orchestrator, output_writer):
        self.command_history_orchestrator = command_history_orchestrator
        self.output_writer = output_writer

    def _resolve_cwd_end(self, cwd_end_provider=None) -> str:
        cwd_end = ''
        if callable(cwd_end_provider):
            cwd_end = cwd_end_provider() or ''
        return cwd_end

    def _finalize_history(self, session: ClientSession, history_entry_id: str, final_ok: bool, cwd_end_provider=None):
        if not history_entry_id:
            return

        self.command_history_orchestrator.finalize_execution(
            session,
            history_entry_id,
            final_ok,
            cwd_end=self._resolve_cwd_end(cwd_end_provider),
        )

    # add command执行主链统一编排扩展 2026-04-09
    def execute_bound(
        self,
        session: ClientSession,
        command_executor,
        cmd: str,
        *,
        history_entry_id: str = '',
        output_writer=None,
        cwd_end_provider=None,
        finalize_history: bool = True,
        swallow_exception: bool = False,
    ) -> bool:
        writer = output_writer or self.output_writer
        final_ok = True

        try:
            func = command_executor.process_command(cmd, history_entry_id=history_entry_id)
            if func:
                for item in func():
                    status = item[0]
                    writer(*item)
                    if status == 0:
                        final_ok = False
        except Exception as e:
            final_ok = False
            if swallow_exception:
                writer(0, str(e))
            else:
                raise
        finally:
            if finalize_history:
                self._finalize_history(
                    session,
                    history_entry_id,
                    final_ok,
                    cwd_end_provider=cwd_end_provider,
                )

        return final_ok

    # add command执行主链统一编排 2026-04-09
    def execute(
        self,
        session: ClientSession,
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
        )