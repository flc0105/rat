import ntpath
import os
from typing import Generator, Optional

from core.protocol.message_queue import MessageQueue, PendingCommandQueue, ReadySignalQueue
from core.protocol.ratsocket import RATSocket
from core.utils.files import get_output_stream, get_input_stream
from core.utils.logger import logger, get_file_logger
from server.config.config import BACKGROUND_MESSAGE_OUTPUT_TO_FILE, SHOW_MESSAGES_FROM_OTHER_CONNECTIONS

if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
    file_logger = get_file_logger('background_messages.log')


class ClientConnection(RATSocket):
    """
    封装每个客户端连接的对象
    """

    def __init__(self, sock, address=None, info=None):
        super().__init__()
        self.socket = sock  # 客户端套接字
        self.address = address  # 客户端地址
        self.info = info or {}  # 客户端信息

        self.pending_command_ids = PendingCommandQueue()  # 等待结果的命令ID队列
        self.message_queue = MessageQueue()  # 命令结果/未读消息队列
        self.ready_queue = ReadySignalQueue()  # 文件传输就绪信号队列
        self.is_interactive = False  # 是否处于交互会话中
        self._message_id_counter = 0  # 连接内消息自增 ID
        # self.command_history = [] # 命令执行历史记录

    # ------------------ ID/构包 ------------------ #
    def _generate_message_id(self) -> int:
        """
        生成连接内唯一的消息 ID
        """
        self._message_id_counter += 1
        return self._message_id_counter

    def _build_command_payload(self, command: str, command_type: str = 'command', extra=None) -> dict:
        """
        构造命令消息
        """
        data = {
            'type': command_type,
            'id': self._generate_message_id(),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        return data

    def _build_file_payload(self, filename: str) -> dict:
        """
        构造文件消息头
        """
        return {
            'type': 'file',
            'id': self._generate_message_id(),
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
        }

    # ------------------ 发送命令/文件 ------------------ #
    def send_command(self, command: str, type='command', extra=None) -> Generator:
        """
        向客户端发送命令
        :param command: 命令
        :param type: 命令类型
        :param extra: 额外信息
        :return: 结果生成器
        """
        data = self._build_command_payload(command, type, extra)
        self.send(data)
        return self.wait_for_result(data.get('id'), command if type == 'command' else None)

    def send_file(self, filename: str) -> Generator:
        """
        向客户端发送文件
        :param filename: 文件名
        :return: 结果生成器
        """
        data = self._build_file_payload(filename)
        io = get_output_stream(filename)

        self.send(data)  # 发送文件请求头
        if self.ready_queue.get():  # 如果对方就绪
            self.send_io(io)  # 发送文件

        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    # ------------------ 接收消息 ------------------ #
    def _handle_ready_message(self, data: dict) -> None:
        """
        处理文件传输就绪信号
        """
        self.ready_queue.put(data.get('status'))

    def _handle_result_message(self, data: dict) -> None:
        """
        处理命令执行结果消息
        """
        self.info['cwd'] = data.get('cwd')
        self.process_command_result(
            data.get('id'),
            data.get('status'),
            data.get('text'),
            data.get('eof')
        )

    def _handle_file_message(self, data: dict) -> None:
        """
        处理客户端上传的文件消息
        """
        self.info['cwd'] = data.get('cwd')
        self.process_command_result(
            data.get('id'),
            *self.save_file(data.get('filename'), data.get('length')),
            end=1
        )

    def _dispatch_received_message(self, data: dict) -> None:
        """
        根据消息类型分发处理
        """
        msg_type = data.get('type')

        if msg_type == 'rdy':
            self._handle_ready_message(data)
            return

        if msg_type == 'result':
            self._handle_result_message(data)
            return

        if msg_type == 'file':
            self._handle_file_message(data)
            return

    def recv_message(self):
        """
        子线程接收消息并处理
        """
        data = self.recv()
        self._dispatch_received_message(data)

    def save_file(self, filename, length):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        file = os.path.abspath(filename)
        try:
            io = get_input_stream(file)
            try:
                self.send_signal(1)
                self.recv_io(length, io)
                return 1, f'File saved to: {file}'
            except Exception as e:
                return 0, f'Error receiving file from {self.address}: {e}'
        except Exception as e:
            self.send_signal(0)
            return 0, f'Error opening local file: {e}'

    # ------------------ 处理结果 ------------------ #
    def _enqueue_expected_result(self, status, text, end) -> None:
        """
        将预期命令结果写入结果队列
        """
        self.message_queue.put(status, text, end)

    def _is_expected_result(self, command_id) -> bool:
        """
        判断当前结果是否属于队首等待中的命令
        """
        pending_id = self.pending_command_ids.peek_first()
        return command_id == pending_id

    def process_command_result(self, command_id, status, text, end):
        """
        处理命令执行结果
        :param command_id: 命令id
        :param status: 状态
        :param text: 结果文本
        :param end: 是否结束
        """
        if self._is_expected_result(command_id):
            self._enqueue_expected_result(status, text, end)
            return

        self.handle_unexpected_message(status, text, end)

    def handle_unexpected_message(self, status, text, end):
        """
        处理非预期消息
        """
        if self.is_interactive:
            if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
                file_logger.info(f'Message from {self.address}: {text}')
            else:
                logger.info(text)
            return

        if BACKGROUND_MESSAGE_OUTPUT_TO_FILE:
            file_logger.info(f'Message from {self.address}: {text}')
            return

        if SHOW_MESSAGES_FROM_OTHER_CONNECTIONS:
            logger.info(f'Message from {self.address}: {text}')
        else:
            self.message_queue.put(status, text, end)

    # ------------------ 等待结果 ------------------ #
    def wait_for_result(self, id: int, command: Optional[str]):
        """
        主线程等待接收结果，并保存执行记录
        :param id: 命令id
        :param command: 命令文本
        :return: 结果生成器
        """
        self.pending_command_ids.put(id)  # 将命令id加入待执行队列

        while 1:
            status, result, eof = self.message_queue.get()
            yield status, result
            if eof:
                self.pending_command_ids.get()
                break