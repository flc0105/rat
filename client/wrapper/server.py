import ntpath
import os

from client.util.command import CommandExecutor
from common.ratsocket import RATSocket
from common.util import logger, get_input_stream, get_output_stream


class Server(RATSocket):

    def __init__(self):
        super().__init__()
        self.command_executor = CommandExecutor(self)

    def send_result(self, id: int, status: int, result: str, eof: int = 1):
        """
        向服务端发送结果
        :param id: 与命令id对应
        :param status: 0或1
        :param result: 结果
        :param eof: 是否结束
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
        :param id: 与命令id对应
        :param filename: 文件名
        """
        data = {
            'type': 'file',
            'id': id,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
            'cwd': os.getcwd(),
        }
        io = get_output_stream(filename)
        self.send(data)
        if self.recv_signal():
            self.send_io(io)

    def recv_command(self) -> (int, int, str):
        """
        从服务端接收命令并在本地执行
        :return: 结果id，状态，结果
        """
        data = self.recv()
        logger.debug(data)
        id = data.get('id')
        type = data.get('type')
        try:
            # 如果是命令
            if type == 'command':
                result = self.command_executor.execute_command(id, data.get('text'))
                if result:
                    return id, *result

            # 如果是Python脚本
            if type == 'script':
                return id, *self.command_executor.pyexec(data['text'], kwargs=data.get('extra'))

            # 如果是文件
            elif type == 'file':
                return id, *self.save_file(data.get('filename'), data.get('length'))
        except Exception as e:
            logger.error(e, exc_info=True)
            return id, 0, f'{e}\n'

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
