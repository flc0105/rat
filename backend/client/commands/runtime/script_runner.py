from client.commands.runtime.request import CommandExecutionRequest


class ScriptCommandRunner:
    """
    script 消息执行链。

    当前约定：
    - script 默认只走 stream 语义
    - 当前进程 / 子进程由 Python execution strategy 决定
    """

    def __init__(self, executor):
        self.executor = executor

    def execute(self, request: CommandExecutionRequest, script_text: str, kwargs=None):
        def _invoke(commands):
            return commands.execute_script_stream(script_text, kwargs=kwargs)

        return self.executor.execute_bound_request(request, _invoke)
