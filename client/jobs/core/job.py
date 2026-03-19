import threading
import uuid
from abc import ABC, abstractmethod

import requests

from client.config.config import UPLOAD_BASE_URL


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
        self.job_key = ''
        self.is_running = False
        self.stop_event = threading.Event()

        self.upload_url = UPLOAD_BASE_URL + '/api/files/upload'
        self.report_url = UPLOAD_BASE_URL + '/api/background-jobs/report'
        self.client_id = None

    def bind_context(self, server, command_id, client_id=None, job_key=''):
        """
        绑定运行上下文
        """
        self.server = server
        self.command_id = command_id
        self.client_id = client_id
        self.job_key = (job_key or '').strip()

    def _build_display_name(self) -> str:
        display_base = self.job_key or self.job_name or 'job'
        return f'{display_base}#{self.job_id[:8]}'

    def _build_report_payload(self, event_type: str, **extra) -> dict:
        payload = {
            'event_type': event_type,
            'client_id': self.client_id or '',
            'command_id': self.command_id,
            'job_id': self.job_id,
            'job_name': self.job_name,
            'job_key': self.job_key,
            'display_name': self._build_display_name(),
            'thread_name': threading.current_thread().name,
        }
        payload.update(extra)
        return payload

    def _post_job_report(self, payload: dict):
        """
        通过 HTTP 向服务端上报后台任务事件
        """
        if not self.client_id:
            return

        try:
            requests.post(
                self.report_url,
                json=payload,
                timeout=10,
            )
        except Exception:
            # 后台任务不应因为上报失败而崩溃
            pass

    # todo: job线程改成不允许操作socket对象，只能通过http汇报
    # def send_to_server(self, status, message, eof=0):
    #     """
    #     向服务端发送任务输出
    #     """
    #     thread_name = threading.current_thread().name
    #     formatted_message = f'[{self.job_name}#{self.job_id[:8]} @ {thread_name}] {message}'
    #     self.server.send_result(self.command_id, status, formatted_message, eof)

    def send_to_server(self, status, message, eof=0):
        """
        向服务端发送任务输出。
        当前实现改为 HTTP 上报。
        """

        # 旧 socket 发送逻辑保留，先注释掉，方便之后回退
        # if self.server is None:
        #     return
        #
        # if not getattr(self.server, 'is_connected', True):
        #     return
        #
        # thread_name = threading.current_thread().name
        # formatted_message = (
        #     f'[{self.job_name}#{self.job_id[:8]} @ {thread_name} '
        #     f'client={self.client_id}] {message}'
        # )
        #
        # try:
        #     self.server.send_result(self.command_id, status, formatted_message, eof)
        # except OSError:
        #     pass
        # except Exception:
        #     pass

        thread_name = threading.current_thread().name
        formatted_message = (
            f'[{self.job_name}#{self.job_id[:8]} @ {thread_name} '
            f'client={self.client_id}] {message}'
        )

        self._post_job_report(
            self._build_report_payload(
                'message',
                status=status,
                text=formatted_message,
                eof=eof,
            )
        )

    def _report_state(self, state: str, status: int = 1, text: str = ''):
        self._post_job_report(
            self._build_report_payload(
                'status',
                state=state,
                status=status,
                text=text,
            )
        )

    def _report_uploaded_file(self, file_info: dict):
        if not isinstance(file_info, dict):
            return

        artifact_id = (file_info.get('artifact_id') or '').strip()
        if not artifact_id:
            return

        self._post_job_report(
            self._build_report_payload(
                'file',
                file={
                    'artifact_id': artifact_id,
                    'artifact_type': file_info.get('artifact_type', ''),
                    'original_name': file_info.get('original_name', ''),
                    'stored_name': file_info.get('stored_name', ''),
                    'relative_path': file_info.get('relative_path', ''),
                    'size': file_info.get('size', 0),
                    'category': file_info.get('category', ''),
                    'download_url': file_info.get('download_url', ''),
                    'raw_url': file_info.get('raw_url', ''),
                    'preview_url': file_info.get('preview_url', ''),
                }
            )
        )

    def upload_file_via_http(self, file_path, category=None):
        with open(file_path, 'rb') as file_obj:
            response = requests.post(
                self.upload_url,
                files={'file': file_obj},
                data={
                    'category': category,
                    'client_id': self.client_id,
                    'hostname': getattr(self.server, 'info', {}).get('hostname', '') if self.server else '',
                    'job_id': self.job_id,
                    'job_name': self.job_name,
                    'job_key': self.job_key,
                },
                timeout=30,
            )

        try:
            payload = response.json()
        except Exception:
            payload = None

        if response.ok and isinstance(payload, dict):
            file_info = payload.get('data') or {}
            if isinstance(file_info, dict):
                self._report_uploaded_file(file_info)

        return response

    def mark_running(self):
        self.is_running = True
        self.stop_event.clear()
        self._report_state('running', status=1, text='Job started')

    def mark_stopped(self):
        self.is_running = False
        self.stop_event.set()
        self._report_state('stopped', status=1, text='Job stopped')

    @abstractmethod
    def run(self):
        """
        任务主逻辑
        """
        raise NotImplementedError

    def request_stop(self, notify: bool = True):
        """
        请求任务停止。

        Args:
            notify: 是否向服务端发送停止通知。
        """
        if self.is_running and notify:
            try:
                self._report_state('stopping', status=1, text='Stop requested')
                self.send_to_server(1, 'Stop requested', 0)
            except Exception:
                pass

        self.is_running = False
        self.stop_event.set()

    def stop(self, notify: bool = True):
        """
        默认停止逻辑；子类可覆盖扩展
        """
        self.request_stop(notify=notify)
