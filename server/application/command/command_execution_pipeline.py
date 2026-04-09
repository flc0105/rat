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

        final_ok = True

        try:
            func = command_executor.process_command(cmd, history_entry_id=entry_id)
            if func:
                for item in func():
                    status = item[0]
                    self.output_writer(*item)
                    if status == 0:
                        final_ok = False
        except Exception:
            final_ok = False
            raise
        finally:
            cwd_end = ''
            if callable(cwd_end_provider):
                cwd_end = cwd_end_provider() or ''

            self.command_history_orchestrator.finalize_execution(
                session,
                entry_id,
                final_ok,
                cwd_end=cwd_end,
            )

        return final_ok