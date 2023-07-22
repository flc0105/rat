import json
import os
import socket
import struct
from typing import BinaryIO

from common.util import draw_progress_bar


class RATSocket:

    def __init__(self):
        self.socket = socket.socket()

    def connect(self, address):
        """连接"""
        return self.socket.connect_ex(address) == 0

    def bind(self, address):
        """绑定"""
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        self.socket.listen(5)

    def accept(self):
        """接受连接"""
        return self.socket.accept()

    def close(self):
        """关闭连接"""
        self.socket.close()

    def send(self, data: dict):
        """
        发送消息
        :param data: 消息
        """
        data = json.dumps(data).encode()
        self.socket.send(struct.pack('i', len(data)) + data)

    def send_io(self, io: BinaryIO, total=None):
        """
        发送文件
        :param io: 文件流
        """

        if not total:
            total = os.fstat(io.fileno()).st_size

        bytes_read = 0
        buffer_size = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        while 1:
            data = io.read(buffer_size)
            if not data:
                break
            self.socket.send(data)
            bytes_read += len(data)
            draw_progress_bar(bytes_read, total)
        io.close()

    def recv(self) -> dict:
        """
        接收消息
        :return: 消息
        """
        length = self.socket.recv(4)
        if not length:
            raise socket.error('Receiving failure')
        length = struct.unpack('i', length)[0]
        data = b''
        while length:
            buf = self.socket.recv(length)
            if not buf:
                raise socket.error('Connection aborted')
            length -= len(buf)
            data += buf
        return json.loads((data.decode()))

    def recv_io(self, length: int, io: BinaryIO):
        """
        接收文件
        :param length: 接收长度
        :param io: 文件流
        """
        bytes_left = length
        while bytes_left:
            buf = self.socket.recv(bytes_left)
            if not buf:
                raise socket.error('Connection aborted')
            bytes_left -= len(buf)
            draw_progress_bar(length - bytes_left, length)
            io.write(buf)
        io.close()

    def send_signal(self, status: int):
        """
        发送就绪信号
        :param status: 0或1
        """
        self.send({
            'type': 'rdy',
            'status': status
        })

    def recv_signal(self) -> int:
        """
        接收就绪信号
        :return: 0或1
        """
        return self.recv()['status']
