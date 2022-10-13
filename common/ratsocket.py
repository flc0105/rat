import json
import socket
import struct


class RATSocket:

    def __init__(self):
        self.socket = socket.socket()

    def connect(self, address):
        """ 连接 """
        return self.socket.connect_ex(address) == 0

    def bind(self, address):
        """ 绑定 """
        self.socket.bind(address)
        self.socket.listen(5)

    def accept(self, connection_handler, func=None):
        """ 接受连接 """
        while True:
            connection_handler(*self.socket.accept(), func)

    def close(self):
        """ 关闭连接 """
        self.socket.close()

    def send(self, head: dict, body: bytes):
        """ 发送 """
        # 将请求头转换为字节
        head = json.dumps(head).encode()
        # 发送请求头长度、请求头和主体
        self.socket.send(struct.pack('i', len(head)) + head + body)

    def recv(self):
        """ 接收 """
        # 获得请求头的长度
        head_len = self.socket.recv(4)
        if not head_len:
            raise socket.error('Receiving failure')
        head_len = struct.unpack('i', head_len)[0]
        # 接收请求头
        head = json.loads((self.socket.recv(head_len).decode()))
        # 接收主体
        body_len = head['length']
        body = b''
        while body_len:
            buf = self.socket.recv(body_len)
            body_len -= len(buf)
            body += buf
        # 返回请求头和主体
        return head, body
