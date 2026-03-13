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

    def _dynamic_import(self, module):
        # 获取模块路径
        full_path = os.path.abspath(os.path.join(JOB_PATH, module))

        # 检查文件是否存在
        if not os.path.isfile(full_path):
            raise FileNotFoundError(f'File does not exist: {full_path}')

        module_name, _ = os.path.splitext(os.path.basename(full_path))

        try:
            # 导入模块
            spec = importlib.util.spec_from_file_location(module_name, full_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 获取主类
            cls = get_main_class(module, module_name)

            # 实例化类并设置参数
            instance = cls.get_instance()
            instance.set_args(self.socket, self.command_id)

            # 缓存实例化后的类对象
            self.jobs[module_name] = instance
            return instance
        except Exception as e:
            raise ImportError(f'Failed to import module {module_name}: {str(e)}')
