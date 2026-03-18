import ntpath
import os
from typing import Generator, Optional

from core.protocol.base_connection import BaseSessionConnection
from core.protocol.message_queue import MessageQueue, PendingCommandQueue
from server.connection.file_receiver import ClientFileReceiver
from server.connection.message_router import ClientMessageRouter
from server.connection.result_dispatcher import ClientResultDispatcher


class ClientConnection(BaseSessionConnection):
    """
    封装每个客户端连接的对象
    """

    FILE_TRANSFER_REJECTED_MESSAGE = 'Client rejected file transfer'

    def __init__(self, sock, address=None, info=None, file_save_dir=None, on_file_saved=None):
        super().__init__()
        self.socket = sock
        self.address = address
        self.info = info or {}

        self.pending_command_ids = PendingCommandQueue()
        self.message_queue = MessageQueue()
        self.is_interactive = False
        self._message_id_counter = 0

        self._file_receive_contexts = {}

        # web
        self.on_unexpected_message = None

        # web files
        self.file_save_dir = file_save_dir
        self.on_file_saved = on_file_saved

        # helpers
        self.result_dispatcher = ClientResultDispatcher(self)
        self.message_router = ClientMessageRouter(self)
        self.file_receiver = ClientFileReceiver(self)

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

    def _build_file_payload(self, filename: str, save_dir: str = '') -> dict:
        """
        构造文件消息头
        """
        data = {
            'type': 'file',
            'id': self._generate_message_id(),
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
        }
        if save_dir:
            data['save_dir'] = save_dir
        return data

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

    def send_file(self, filename: str, save_dir: str = '') -> Generator:
        """
        向客户端发送文件
        :param filename: 文件名
        :return: 结果生成器
        """
        data = self._build_file_payload(filename, save_dir)
        self.send_file_by_header(data, filename)
        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    def handle_received_message(self, data: dict):
        """
        处理接收线程收到的消息
        """
        self.message_router.dispatch(data)
        return None

    def set_file_receive_context(self, command_id: int, **context):
        """
        为指定命令设置文件接收上下文
        """
        self._file_receive_contexts[command_id] = context

    def pop_file_receive_context(self, command_id: int):
        """
        取出并删除指定命令的文件接收上下文
        """
        return self._file_receive_contexts.pop(command_id, None)

    def save_file(self, command_id, filename, length):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        return self.file_receiver.save_file(command_id, filename, length)

    def wait_for_result(self, id: int, command: Optional[str]):
        """
        主线程等待接收结果，并保存执行记录
        :param id: 命令id
        :param command: 命令文本
        :return: 结果生成器
        """
        self.pending_command_ids.put(id)

        while 1:
            status, result, eof = self.message_queue.get()
            yield status, result
            if eof:
                self.pending_command_ids.get()
                break