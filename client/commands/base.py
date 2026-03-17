from abc import ABC

from client.jobs.core.manager import JobManager


class CommandBase(ABC):
    """命令基类，定义公共接口"""

    def __init__(self, socket):
        self.socket = socket
        self.command_id = None
        # self.job_manager = JobManager(socket)

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