
import json
import os
import socket
import struct
from typing import BinaryIO, Optional

from core.utils.common_util import draw_progress_bar


class RATSocket:
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        self.socket = socket.socket(family, type, proto)

    # ------------------ 基础连接操作 ------------------ #
    def connect(self, address: tuple) -> bool:
        """连接服务器"""
        result = self.socket.connect_ex(address)
        print(f'connect_result={result}')
        return result == 0

    def bind(self, address: tuple, backlog: int = 5) -> None:
        """绑定并监听"""
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        self.socket.listen(backlog)

    def accept(self) -> tuple:
        """接受连接"""
        return self.socket.accept()

    def close(self) -> None:
        """关闭连接"""
        self.socket.close()

    # ------------------ 消息发送接收 ------------------ #
    def send(self, data: dict) -> None:
        """发送字典消息"""
        encoded = json.dumps(data).encode()
        self._send_bytes(encoded)

    def recv(self) -> dict:
        """接收字典消息"""
        data = self._recv_bytes()
        return json.loads(data.decode())

    # ------------------ 文件发送接收 ------------------ #
    def send_io(self, io: BinaryIO, total: Optional[int] = None, buffer_size: Optional[int] = None) -> None:
        """发送文件"""
        if total is None:
            total = os.fstat(io.fileno()).st_size
        if buffer_size is None:
            buffer_size = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

        bytes_sent = 0
        while True:
            chunk = io.read(buffer_size)
            if not chunk:
                break
            self._send_bytes(chunk, raw=True)
            bytes_sent += len(chunk)
            draw_progress_bar(bytes_sent, total)
        io.close()

    def recv_io(self, length: int, io: BinaryIO, buffer_size: Optional[int] = 4096) -> None:
        """接收文件"""
        bytes_left = length
        while bytes_left > 0:
            chunk = self.socket.recv(min(buffer_size, bytes_left))
            if not chunk:
                raise socket.error("Connection aborted")
            bytes_left -= len(chunk)
            draw_progress_bar(length - bytes_left, length)
            io.write(chunk)
        io.close()

    # ------------------ 信号 ------------------ #
    def send_signal(self, status: int) -> None:
        """发送就绪信号"""
        self.send({'type': 'rdy', 'status': status})

    def recv_signal(self) -> int:
        """接收就绪信号"""
        return self.recv()['status']

    # ------------------ 私有方法 ------------------ #
    def _send_bytes(self, data: bytes, raw: bool = False) -> None:
        """
        发送字节流
        :param data: 数据
        :param raw: True时直接发送，不添加长度前缀
        """
        if not raw:
            self.socket.sendall(struct.pack('i', len(data)))
        self.socket.sendall(data)

    def _recv_bytes(self) -> bytes:
        """接收字节流（带长度前缀）"""
        header = self.socket.recv(4)
        if not header:
            raise socket.error("Connection closed")
        length = struct.unpack('i', header)[0]

        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise socket.error("Connection aborted")
            data += chunk
        return data