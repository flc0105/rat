import ntpath
import os
import queue

from client.commands.common import CommonCommands
from client.commands.executor import CommandExecutor
from client.connection.file_receiver import ServerFileReceiver
from client.connection.message_dispatcher import ClientInboundMessageDispatcher
from client.connection.message_router import ClientInboundMessageRouter
from client.jobs.core.manager import JobManager
from core.protocol.base_connection import BaseSessionConnection
from core.utils.logger import logger


class ServerConnection(BaseSessionConnection):
    """
    客户端与服务端的连接类
    负责接收命令、发送结果/文件、执行命令
    """

    FILE_TRANSFER_REJECTED_MESSAGE = 'Server rejected file transfer'

    def __init__(self):
        super().__init__()
        self.client_id = None

        self.command_executor = CommandExecutor(self)
        self.pending_message_queue = queue.Queue()

        self.job_manager = JobManager(self)
        self.is_connected = False

        self.message_router = ClientInboundMessageRouter(self)
        self.message_dispatcher = ClientInboundMessageDispatcher(self)
        self.file_receiver = ServerFileReceiver(self)

    def mark_connected(self):
        self.is_connected = True

    def mark_disconnected(self):
        self.is_connected = False

    def reset_runtime_state(self):
        """
        清理当前连接相关运行态
        """
        self.reset_transfer_runtime()

        try:
            while True:
                self.pending_message_queue.get_nowait()
        except queue.Empty:
            pass
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

    def _build_outbound_file_header(self, command_id: int, filename: str) -> dict:
        """
        构造发送到服务端的文件头
        """
        return {
            'type': 'file',
            'id': command_id,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'cwd': os.getcwd(),
        }

    def send_file(self, id: int, filename: str):
        """
        向服务端发送文件
        """
        header = self._build_outbound_file_header(id, filename)
        self.send_file_by_header(header, filename)

    def enqueue_pending_message(self, data: dict):
        """
        将需由主线程执行的消息放入待处理队列
        """
        self.pending_message_queue.put(data)

    def handle_received_message(self, data: dict):
        """
        处理接收线程收到的消息。

        返回值：
        - None: 该消息已处理完成，调用方无需额外动作
        - tuple: 需要由接收线程立即 send_result(*result)
        """
        logger.debug(data)
        return self.message_dispatcher.dispatch(data)

    def recv_command(self, timeout: float | None = None) -> (int, int, str):
        """
        从待处理队列中取出一条消息并执行
        """
        data = self.pending_message_queue.get(timeout=timeout)

        try:
            return self.message_router.dispatch(data)
        except Exception as e:
            logger.error(e, exc_info=True)
            return data.get('id'), 0, f'{e}\n'