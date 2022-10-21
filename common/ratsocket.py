import json
import socket
import struct
from typing import BinaryIO


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

    def send(self, head: dict, body: bytes = None, f: BinaryIO = None, update_progress=None):
        """ 发送数据 """
        # 将请求头转换为字节
        head_str = json.dumps(head).encode()
        # 发送文件
        if head['type'] in ['file', 'script']:
            # 发送请求头
            self.socket.send(struct.pack('i', len(head_str)) + head_str)
            # 已发送长度
            bytes_read = 0
            # 文件长度
            length = head['length']
            # 一次读取发送的大小
            buffer_size = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            while True:
                # 从文件中读取指定长度
                data = f.read(buffer_size)
                # 全部发送完成后退出循环
                if not data:
                    break
                # 发送从文件中读取的字节
                self.socket.send(data)
                # 更新已发送长度
                bytes_read += len(data)
                # 更新进度条
                if update_progress is not None:
                    update_progress(bytes_read, length)
        # 发送文本
        else:
            # 依次发送请求头长度、请求头和消息主体
            self.socket.send(struct.pack('i', len(head_str)) + head_str + body)

    def recv_head(self) -> dict:
        """ 接收请求头 """
        # 接收4个字节的请求头长度
        head_len = self.socket.recv(4)
        if not head_len:
            raise socket.error('Receiving failure')
        # 获得请求头长度
        head_len = struct.unpack('i', head_len)[0]
        # 接收请求头
        return json.loads((self.socket.recv(head_len).decode()))

    def recv_body(self, head: dict, f: BinaryIO = None, update_progress=None) -> str:
        """接收消息主体"""
        # 获取主体长度
        length = head['length']
        # 接收文件
        if head['type'] == 'file':
            # 剩余接收长度
            recv_size = length
            while recv_size:
                # 接收剩余长度的数据
                buf = self.socket.recv(recv_size)
                # 更新剩余接收长度
                recv_size -= len(buf)
                # 更新进度条
                if update_progress is not None:
                    update_progress(length - recv_size, length)
                # 写入文件
                f.write(buf)
        # 接收文本
        else:
            body = b''
            while length:
                buf = self.socket.recv(length)
                length -= len(buf)
                body += buf
            # 返回消息主体
            return body.decode()
