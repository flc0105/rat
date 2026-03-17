import threading
import uuid
from abc import ABC, abstractmethod

import requests

from client.config.config import  UPLOAD_BASE_URL


class Job(ABC):
    """
    后台任务基类。

    每次启动任务时都应创建新的任务实例，
    不要在任务类内部维护单例。
    """

    def __init__(self):
        self.server = None
        self.command_id = None
        self.job_id = str(uuid.uuid4())
        self.job_name = self.__class__.__name__
        self.is_running = False
        self.stop_event = threading.Event()

        self.upload_url = UPLOAD_BASE_URL + '/api/files/upload'
        self.client_id=None

    def bind_context(self, server, command_id, client_id=None):
        """
        绑定运行上下文
        """
        self.server = server
        self.command_id = command_id

        self.client_id=client_id

    # todo: job线程改成不允许操作socket对象，只能通过http汇报
    def send_to_server(self, status, message, eof=0):
        """
        向服务端发送任务输出
        """
        thread_name = threading.current_thread().name
        formatted_message = f'[{self.job_name}#{self.job_id[:8]} @ {thread_name}] {message}'
        self.server.send_result(self.command_id, status, formatted_message, eof)

    def upload_file_via_http(self, file_path,  category=None):
        print("client_Id:" + self.client_id)
        with open(file_path, 'rb') as file_obj:
            response = requests.post(
                self.upload_url,
                files={'file': file_obj},
                data={
                    "category": category,
                    "client_id": self.client_id,
                },
                timeout=30,
            )
        return response

    def mark_running(self):
        self.is_running = True
        self.stop_event.clear()

    def mark_stopped(self):
        self.is_running = False
        self.stop_event.set()

    def request_stop(self):
        """
        请求任务停止
        """
        if self.is_running:
            self.send_to_server(1, 'Stop requested', 0)
        self.mark_stopped()

    @abstractmethod
    def run(self):
        """
        任务主逻辑
        """
        raise NotImplementedError

    def stop(self):
        """
        默认停止逻辑；子类可覆盖扩展
        """
        self.request_stop()
