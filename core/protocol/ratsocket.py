import json
import os
import socket
import struct
import threading
from typing import BinaryIO, Optional

from core.utils.formatting import draw_progress_bar


class RATSocket:
    HEADER_FORMAT = 'i'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    DEFAULT_RECV_IO_BUFFER_SIZE = 4096



    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        self.socket = socket.socket(family, type, proto)

        self._send_lock = threading.RLock()

    # ------------------ 基础连接操作 ------------------ #
    def connect(self, address: tuple) -> bool:
        """连接服务器"""
        result = self.socket.connect_ex(address)
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
    # def send(self, data: dict) -> None:
    #     """发送字典消息"""
    #     encoded = json.dumps(data).encode()
    #     self._send_packet(encoded)

    def send(self, data: dict) -> None:
        """发送字典消息"""
        encoded = json.dumps(data).encode()
        with self._send_lock:
            self._send_packet(encoded)


    def recv(self) -> dict:
        """接收字典消息"""
        data = self._recv_packet()
        return json.loads(data.decode())

    # ------------------ 文件发送接收 ------------------ #
    def send_io(self, io: BinaryIO, total: Optional[int] = None, buffer_size: Optional[int] = None) -> None:
        """发送文件"""
        total = self._resolve_send_total(io, total)
        buffer_size = self._resolve_send_buffer_size(buffer_size)

        bytes_sent = 0
        with self._send_lock:
            while True:
                chunk = io.read(buffer_size)
                if not chunk:
                    break
                self._send_raw(chunk)
                bytes_sent += len(chunk)
                draw_progress_bar(bytes_sent, total)
        io.close()

    def recv_io(self, length: int, io: BinaryIO, buffer_size: Optional[int] = None) -> None:
        """接收文件"""
        buffer_size = self._resolve_recv_buffer_size(buffer_size)

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


    # ------------------ 包级发送接收 ------------------ #
    def _send_packet(self, data: bytes) -> None:
        """
        发送带长度前缀的数据包
        """
        self.socket.sendall(struct.pack(self.HEADER_FORMAT, len(data)))
        self.socket.sendall(data)

    def _recv_packet(self) -> bytes:
        """
        接收带长度前缀的数据包
        """
        header = self._recv_exactly(self.HEADER_SIZE)
        length = struct.unpack(self.HEADER_FORMAT, header)[0]
        return self._recv_exactly(length)

    def _send_raw(self, data: bytes) -> None:
        """
        直接发送原始字节流，不附带长度前缀
        """
        self.socket.sendall(data)

    def _recv_exactly(self, size: int) -> bytes:
        """
        精确读取指定字节数；如果连接中断则抛出异常
        """
        chunks = []
        bytes_remaining = size

        while bytes_remaining > 0:
            chunk = self.socket.recv(bytes_remaining)
            if not chunk:
                if bytes_remaining == size:
                    raise socket.error("Connection closed")
                raise socket.error("Connection aborted")
            chunks.append(chunk)
            bytes_remaining -= len(chunk)

        return b''.join(chunks)

    def _resolve_send_total(self, io: BinaryIO, total: Optional[int]) -> int:
        """
        解析发送文件时的总大小
        """
        if total is not None:
            return total
        return os.fstat(io.fileno()).st_size

    def _resolve_send_buffer_size(self, buffer_size: Optional[int]) -> int:
        """
        解析发送文件时的缓冲区大小
        """
        if buffer_size is not None:
            return buffer_size
        return self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

    def _resolve_recv_buffer_size(self, buffer_size: Optional[int]) -> int:
        """
        解析接收文件时的缓冲区大小
        """
        if buffer_size is not None:
            return buffer_size
        return self.DEFAULT_RECV_IO_BUFFER_SIZE