from server.application.command.executor import CommandExecutor


class CommandExecutorFactory:
    """
    CommandExecutor 工厂。

    职责：
    - 统一为不同调用场景创建 CommandExecutor
    - 统一注入共享依赖，避免调用方各自 new 内部依赖

    场景：
    - Web task runner
    - Web facade 命令候选
    - CLI interactive foreground command
    """

    def __init__(self, server, remote_execution_service):
        self.server = server
        self.remote_execution_service = remote_execution_service

    def create(self, conn, *, use_foreground_guard: bool = False, foreground_source: str = 'cli'):
        return CommandExecutor(
            conn,
            self.server,
            remote_execution_service=self.remote_execution_service,
            use_foreground_guard=use_foreground_guard,
            foreground_source=foreground_source,
        )