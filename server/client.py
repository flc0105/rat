import ntpath
import os
import queue
import time
import uuid

from common.ratsocket import RATSocket
from common.util import get_output_stream, get_input_stream, logger


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s
        self.address = address
        self.id = str(uuid.uuid4())  # 客户端id
        self.info = info  # 客户端信息
        self.commands = queue.Queue()  # 存放待执行命令
        self.queue = queue.Queue()  # 存放未读消息
        self.status = False  # 是否正在交互
        self.history = {}  # 存放历史记录

    def send_command(self, command: str, type='command', extra=None) -> int:
        """
        向客户端发送命令
        :param command: 命令
        :param type: 命令类型
        :param extra: 额外信息
        :return: 命令id
        """
        data = {
            'type': type,
            'id': int(time.time()),
            'text': command,
        }
        if extra:
            data['extra'] = extra
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
            'filename': ntpath.basename(filename),
        }
        io = get_output_stream(filename)
        self.send(data)  # 发送文件请求头
        status, _ = self.queue.get()  # 接收确认消息
        if status:  # 如果对方就绪
            self.send_io(io)  # 发送文件

    def recv_result(self):
        """
        从客户端接收结果
        """
        result = None
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
            result = data['status'], data['text'], data['eof']
        # 如果是文件
        elif type == 'file':
            filename = os.path.abspath(data['filename'])
            try:
                io = get_input_stream(filename)
                try:
                    self.send_signal(1)
                    self.recv_io(data['length'], io)
                    result = 1, f'File saved to: {filename}', 1
                except Exception as e:
                    result = 0, f'Error receiving file from {self.address}: {e}', 1
            except Exception as e:
                self.send_signal(0)
                result = 0, f'Error opening local file: {e}', 1
        if result:
            pending_id = 0
            if not self.commands.empty():
                pending_id = self.commands.queue[0]
            if self.status and (id != pending_id):
                logger.info(result)
            else:
                self.queue.put(result)
