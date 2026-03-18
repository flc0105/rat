import ntpath
import os

from client.commands.common import CommonCommands
from client.commands.executor import CommandExecutor
from client.connection.file_receiver import ServerFileReceiver
from client.connection.message_router import ServerMessageRouter
from client.jobs.core.manager import JobManager
from core.protocol.message_queue import ReadySignalQueue
from core.protocol.ratsocket import RATSocket
from core.utils.files import get_output_stream
from core.utils.logger import logger


class ServerConnection(RATSocket):
    """
    客户端与服务器的连接类
    负责接收命令、发送结果/文件、执行命令
    """

    def __init__(self):
        super().__init__()
        self.client_id = None

        self.command_executor = CommandExecutor(self)
        self.ready_queue = ReadySignalQueue()
        self.common_commands = CommonCommands(self)

        self.job_manager = JobManager(self)
        self.is_connected = False

        self.message_router = ServerMessageRouter(self)
        self.file_receiver = ServerFileReceiver(self)

    def mark_connected(self):
        self.is_connected = True

    def mark_disconnected(self):
        self.is_connected = False

    def reset_runtime_state(self):
        """
        清理当前连接相关运行态
        """
        try:
            self.ready_queue.clear()
        except Exception:
            pass

    def send_result(self, id: int, status: int, result: str, eof: int = 1):
        """
        向服务端发送结果
        """
        data = {
            'type': 'result',
            'id': id,
            'status': status,
            'text': result,
            'cwd': os.getcwd(),
            'eof': eof,
        }
        logger.debug(data)
        self.send(data)

    def send_file(self, id: int, filename: str):
        """
        向服务端发送文件
        """
        header = {
            'type': 'file',
            'id': id,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'cwd': os.getcwd(),
        }
        io = get_output_stream(filename)
        self.send(header)
        if self.recv_signal():
            self.send_io(io)

    def recv_command(self) -> (int, int, str):
        data = self.recv()
        logger.debug(data)

        try:
            return self.message_router.dispatch(data)
        except Exception as e:
            logger.error(e, exc_info=True)
            return data.get('id'), 0, f'{e}\n'