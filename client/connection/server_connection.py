import ntpath
import os
import queue

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
        self.pending_message_queue = queue.Queue()
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

    def _wait_for_ready_signal(self, command_id: int, timeout: float = 15.0) -> int:
        """
        等待指定命令对应的文件传输 ready 信号
        """
        try:
            return self.ready_queue.get_for_command(command_id, timeout=timeout)
        except Exception:
            raise TimeoutError(f'Timed out waiting for ready signal: command_id={command_id}')

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

        try:
            self.send(header)
            if self._wait_for_ready_signal(id):
                self.send_io(io)
            else:
                io.close()
                raise RuntimeError(f'Server rejected file transfer: command_id={id}')
        except Exception:
            try:
                io.close()
            except Exception:
                pass
            raise

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

        message_type = data.get('type')

        if message_type == 'rdy':
            self.message_router.dispatch(data)
            return None

        if message_type == 'file':
            return self.message_router.dispatch(data)

        self.enqueue_pending_message(data)
        return None

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