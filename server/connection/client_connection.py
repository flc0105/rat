import ntpath
import os
import threading
from typing import Generator, Optional

from core.protocol.base_connection import BaseSessionConnection
from core.protocol.message_queue import MessageQueue, PendingCommandQueue
from server.connection.file_receiver import ClientFileReceiver
from server.connection.message_dispatcher import ServerInboundMessageDispatcher
from server.connection.message_router import ServerInboundMessageRouter
from server.connection.result_dispatcher import ServerResultDispatcher
from server.models.artifact import FileReceiveContext


class ClientConnection(BaseSessionConnection):
    """
    封装每个客户端连接的对象
    """

    FILE_TRANSFER_REJECTED_MESSAGE = 'Client rejected file transfer'

    def __init__(self, sock, address=None, info=None, file_save_dir=None, on_file_saved=None):
        super().__init__()
        self.socket = sock
        self.address = address
        self.info = info or {}

        self.pending_command_ids = PendingCommandQueue()
        self.message_queue = MessageQueue()
        self.is_interactive = False
        self._message_id_counter = 0

        self._file_receive_contexts = {}

        self._foreground_lock = threading.RLock()
        self._foreground_task = None

        self._history_binding_lock = threading.RLock()
        self._history_entry_ids_by_command_id = {}
        self.command_history = None

        # web
        self.on_unexpected_message = None

        # web files
        self.file_save_dir = file_save_dir
        self.on_file_saved = on_file_saved

        # helpers
        self.result_dispatcher = ServerResultDispatcher(self)
        self.message_router = ServerInboundMessageRouter(self)
        self.message_dispatcher = ServerInboundMessageDispatcher(self)
        self.file_receiver = ClientFileReceiver(self)

    # ------------------ ID/构包 ------------------ #
    def _generate_message_id(self) -> int:
        """
        生成连接内唯一的消息 ID
        """
        self._message_id_counter += 1
        return self._message_id_counter

    def _build_command_payload(self, command: str, command_type: str = 'command', extra=None) -> dict:
        """
        构造命令消息
        """
        data = {
            'type': command_type,
            'id': self._generate_message_id(),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        return data

    def _build_file_payload(self, filename: str, save_dir: str = '') -> dict:
        """
        构造文件消息头
        """
        data = {
            'type': 'file',
            'id': self._generate_message_id(),
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
        }
        if save_dir:
            data['save_dir'] = save_dir
        return data

    # ------------------ history binding ------------------ #
    def bind_history_entry(self, command_id: int, entry_id: str):
        """
        绑定 command_id -> history entry_id
        """
        if not command_id or not entry_id:
            return

        with self._history_binding_lock:
            self._history_entry_ids_by_command_id[command_id] = entry_id

    def get_history_entry_id(self, command_id: int) -> str:
        """
        获取指定 command_id 绑定的 history entry_id
        """
        with self._history_binding_lock:
            return self._history_entry_ids_by_command_id.get(command_id, '')

    def clear_history_entry(self, command_id: int):
        """
        清理指定 command_id 的历史绑定
        """
        with self._history_binding_lock:
            self._history_entry_ids_by_command_id.pop(command_id, None)

    def append_file_to_history(self, command_id: int, file_info: dict):
        """
        将接收到的文件挂到对应执行记录上
        """
        if self.command_history is None:
            return

        entry_id = self.get_history_entry_id(command_id)
        if not entry_id:
            return

        try:
            self.command_history.append_file_for_connection(self, entry_id, file_info)
        except Exception:
            pass

    def send_command(self, command: str, type='command', extra=None, history_entry_id: str = '') -> Generator:
        """
        向客户端发送命令
        :param command: 命令
        :param type: 命令类型
        :param extra: 额外信息
        :param history_entry_id: 执行记录 entry_id
        :return: 结果生成器
        """
        data = self._build_command_payload(command, type, extra)

        if history_entry_id:
            self.bind_history_entry(data.get('id'), history_entry_id)

        self.send(data)
        return self.wait_for_result(data.get('id'), command if type == 'command' else None)

    def send_file(self, filename: str, save_dir: str = '', history_entry_id: str = '') -> Generator:
        """
        向客户端发送文件
        :param filename: 文件名
        :param history_entry_id: 执行记录 entry_id
        :return: 结果生成器
        """
        data = self._build_file_payload(filename, save_dir)

        if history_entry_id:
            self.bind_history_entry(data.get('id'), history_entry_id)

        self.send_file_by_header(data, filename)
        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    def handle_received_message(self, data: dict):
        """
        处理接收线程收到的消息
        """
        return self.message_dispatcher.dispatch(data)

    def set_file_receive_context(self, command_id: int, **context):
        """
        为指定命令设置文件接收上下文
        """
        self._file_receive_contexts[command_id] = FileReceiveContext.from_dict(context)

    def pop_file_receive_context(self, command_id: int):
        """
        取出并删除指定命令的文件接收上下文
        """
        context = self._file_receive_contexts.pop(command_id, None)
        if isinstance(context, FileReceiveContext):
            return context
        return FileReceiveContext.from_dict(context)

    def save_file(self, command_id, filename, length):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        return self.file_receiver.save_file(command_id, filename, length)

    # client is busy start

    def acquire_foreground_task(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        """
        尝试占用当前连接的前台执行槽。

        Args:
            task_type: 任务类型，如 command / upload
            command: 展示用命令文本
            source: 来源，如 cli / web
            task_id: 可选的 web task_id

        Returns:
            当前占用信息 dict

        Raises:
            RuntimeError: 当前连接已被其他前台任务占用
        """
        task_info = {
            'task_type': task_type,
            'command': (command or '').strip(),
            'source': (source or '').strip(),
            'task_id': (task_id or '').strip(),
        }

        with self._foreground_lock:
            if self._foreground_task is not None:
                current = self._foreground_task
                raise RuntimeError(
                    'Client is busy: '
                    f'{current.get("command") or current.get("task_type") or "running task"}'
                )

            self._foreground_task = task_info
            return dict(task_info)

    def release_foreground_task(self, task_id: str = '', command: str = '') -> None:
        """
        释放当前连接的前台执行槽。

        可按 task_id 或 command 做保护性匹配，避免误释放别人的占用。
        若未传匹配条件，则直接释放当前占用。
        """
        task_id = (task_id or '').strip()
        command = (command or '').strip()

        with self._foreground_lock:
            if self._foreground_task is None:
                return

            current = self._foreground_task

            if task_id and current.get('task_id') and current.get('task_id') != task_id:
                return

            if command and current.get('command') and current.get('command') != command:
                return

            self._foreground_task = None

    def get_foreground_task(self):
        """
        获取当前连接的前台占用信息快照
        """
        with self._foreground_lock:
            if self._foreground_task is None:
                return None
            return dict(self._foreground_task)

    # client is busy end

    def wait_for_result(self, id: int, command: Optional[str]):
        """
        主线程等待接收结果，并保存执行记录
        :param id: 命令id
        :param command: 命令文本
        :return: 结果生成器
        """
        self.pending_command_ids.put(id)

        try:
            while 1:
                status, result, eof = self.message_queue.get()
                yield status, result
                if eof:
                    self.pending_command_ids.get()
                    break
        finally:
            self.clear_history_entry(id)