import importlib.util
import os
from abc import ABC

from client.config.config import JOB_PATH
from core.utils.client_util.reflection_util import get_main_class


class CommandBase(ABC):
    """命令基类，定义公共接口"""

    def __init__(self, socket):
        self.socket = socket
        self.command_id = None

        self.jobs = {}

    def _send_final_result(self, status, result, eof=1):
        self.socket.send_result(self.command_id, status, result, eof)

    def _send_interim_result(self, status, result, eof=0):
        self.socket.send_result(self.command_id, status, result, eof)
