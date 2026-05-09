from client.commands.runtime.request import CommandExecutionRequest


class ArgumentCommandRunner:
    """
    acmd 结构化命令执行链。

    只处理结构化 payload，不和 shell-like command 合并。
    """

    def __init__(self, executor):
        self.executor = executor

    def execute(self, request: CommandExecutionRequest, payload: dict):
        def _invoke(_commands):
            registry = self.executor.get_argument_command_registry()
            return registry.execute(payload)

        return self.executor.execute_bound_request(request, _invoke)
