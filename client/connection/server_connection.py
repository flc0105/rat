import ntpath
import os

from client.commands.common import CommonCommands
from client.commands.executor import CommandExecutor
from core.protocol.message_queue import MessageQueue
from core.protocol.ratsocket import RATSocket
from core.utils.common_util import get_input_stream, get_output_stream
from core.utils.logger import logger


class ServerConnection(RATSocket):
    """
    客户端与服务器的连接类
    负责接收命令、发送结果/文件、执行命令
    """

    def __init__(self):
        super().__init__()
        self.command_executor = CommandExecutor(self)
        self.command_queue = MessageQueue()

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

    def recv_command(self) -> (int, int, str):
        data = self.recv()
        logger.debug(data)
        command_id = data.get('id')
        command_type = data.get('type')
        try:

            # 如果是命令
            if command_type == 'command':
                result = self.command_executor.execute_command(command_id, data.get('text'))  # 在这里把收到的命令id传过去
                if result:
                    return command_id, *result

            # 如果是Python脚本
            if command_type == 'script':
                result = self.common_commands.pyexec(data['text'], kwargs=data.get('extra'))
                return command_id, *result

            # 如果是文件
            if command_type == 'file':
                result = self.save_file(data.get('filename'), data.get('length'))
                return command_id, *result

            # 如果是就绪信号
            if command_type == 'rdy':
                self.command_queue.put(data.get('status'))


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
            logger.error(f'Error receiving file from server: {e}')
