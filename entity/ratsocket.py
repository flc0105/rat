import json
import socket
import struct

from util.common_util import decode


class RATSocket:

    def __init__(self):
        # 创建套接字
        self.socket = socket.socket()

    # 主动连接
    def connect(self, address):
        # 返回连接结果
        return self.socket.connect_ex(address) == 0

    # 被动连接
    def serve(self, address, handler):
        # 绑定地址
        self.socket.bind(address)
        # 监听
        self.socket.listen(5)
        while True:
            # 接受连接并返回给回调函数
            handler(*self.socket.accept())

    # 关闭连接
    def close(self):
        self.socket.close()

    # 发送
    def send(self, head: dict, body: bytes):
        # 将请求头转换为字节
        head = json.dumps(head).encode()
        # 发送请求头长度、请求头和主体
        self.socket.send(struct.pack('i', len(head)) + head + body)

    # 接收
    def recv(self):
        # 获得请求头的长度
        head_len = self.socket.recv(4)
        if not head_len:
            raise Exception('Receiving failure')
        head_len = struct.unpack('i', head_len)[0]
        # 接收请求头
        head = json.loads(decode(self.socket.recv(head_len)))
        # 接收主体
        body_len = head['length']
        body = b''
        while body_len:
            buf = self.socket.recv(body_len)
            body_len -= len(buf)
            body += buf
        # 返回请求头和主体
        return head, body
