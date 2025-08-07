import os
import platform
from abc import ABC, abstractmethod



class CommandBase(ABC):
    """命令基类，定义公共接口"""

    def __init__(self, socket):
        self.socket = socket
        self.command_id = None

    def send_final_result(self, status, result, eof=1):
        self.socket.send_result(self.command_id, status, result, eof)

    def send_interim_result(self, status, result, eof=0):
        self.socket.send_result(self.command_id, status, result, eof)
