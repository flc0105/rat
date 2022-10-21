import ntpath
import os

from common.ratsocket import RATSocket


class Server(RATSocket):

    def __init__(self):
        super().__init__()

    def send_result(self, status: int, result: str):
        """ 向服务端发送命令执行结果 """
        body = result.encode()
        head = {
            'type': 'result',
            'status': status,
            'length': len(body)
        }
        self.send(head, body=body)

    def send_file(self, filename: str):
        """ 向服务端发送文件 """
        head = {
            'type': 'file',
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        with open(filename, 'rb') as f:
            self.send(head, f=f)
