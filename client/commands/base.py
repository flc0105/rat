from abc import ABC

from client.commands.command_context import CommandCancelledError


class CommandBase(ABC):
    """命令基类，定义公共接口。"""

    def __init__(self, socket):
        self.socket = socket
        self.command_id = None
        self.execution_context = None

    def bind_execution(self, command_id, execution_context=None):
        """
        绑定当前命令执行上下文
        """
        self.command_id = command_id
        self.execution_context = execution_context

    def _send_result(self, status, result, eof=1):
        """
        发送当前命令的执行结果
        """
        self.socket.send_result(self.command_id, status, result, eof)

    def _send_final_result(self, status, result, eof=1):
        """
        发送最终结果
        """
        self._send_result(status, result, eof)

    def _send_interim_result(self, status, result, eof=0):
        """
        发送中间结果
        """
        self._send_result(status, result, eof)

    def _get_execution_context(self):
        return self.execution_context

    def _is_cancel_requested(self) -> bool:
        context = self._get_execution_context()
        return bool(context and context.is_cancel_requested())

    def _ensure_not_cancelled(self):
        if self._is_cancel_requested():
            raise CommandCancelledError('Command cancelled')

    def _register_cancel_handler(self, handler):
        context = self._get_execution_context()
        if context is None:
            return
        context.add_cancel_handler(handler)
