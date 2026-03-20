from typing import Optional

from core.protocol.message_queue import MessageQueue, PendingCommandQueue
from server.connection.runtime.foreground_task_guard import ForegroundTaskGuard
from server.connection.runtime.history_binding_store import HistoryBindingStore


class ClientSessionRuntime:
    """
    客户端会话运行时。

    职责：
    - 保存与“本次连接会话运行状态”相关的数据
    - 不直接负责 socket 收发
    - 为 ClientConnection / ClientSessionCommandChannel 提供运行态存取能力

    当前承载：
    - pending_command_ids
    - message_queue
    - foreground_task_guard
    - history_binding_store
    - file_receive_context_store
    """

    def __init__(self):
        self.pending_command_ids = PendingCommandQueue()
        self.message_queue = MessageQueue()

        self._foreground_task_guard = ForegroundTaskGuard()
        self._history_binding_store = HistoryBindingStore()
    # ------------------ history binding ------------------ #
    def bind_history_entry(self, command_id: int, entry_id: str):
        """
        绑定 command_id -> history entry_id
        """
        self._history_binding_store.bind(command_id, entry_id)

    def get_history_entry_id(self, command_id: int) -> str:
        """
        获取指定 command_id 绑定的 history entry_id
        """
        return self._history_binding_store.get(command_id)

    def clear_history_entry(self, command_id: int):
        """
        清理指定 command_id 的历史绑定
        """
        self._history_binding_store.clear(command_id)

    # ------------------ file receive context ------------------ #
    def set_file_receive_context(self, command_id: int, **context):
        """
        为指定命令设置文件接收上下文
        """
        self._file_receive_context_store.set(command_id, **context)

    def pop_file_receive_context(self, command_id: int):
        """
        取出并删除指定命令的文件接收上下文
        """
        return self._file_receive_context_store.pop(command_id)

    # ------------------ foreground task ------------------ #
    def acquire_foreground_task(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        """
        尝试占用当前连接的前台执行槽。
        """
        return self._foreground_task_guard.acquire(
            task_type=task_type,
            command=command,
            source=source,
            task_id=task_id
        )

    def release_foreground_task(self, task_id: str = '', command: str = '') -> None:
        """
        释放当前连接的前台执行槽。
        """
        self._foreground_task_guard.release(task_id=task_id, command=command)

    def get_foreground_task(self):
        """
        获取当前连接的前台占用信息快照
        """
        return self._foreground_task_guard.snapshot()

    # ------------------ result wait ------------------ #
    def wait_for_result(self, connection, command_id: int, command: Optional[str]):
        """
        主线程等待接收结果，并保存执行记录
        """
        self.pending_command_ids.put(command_id)

        try:
            while 1:
                status, result, eof = self.message_queue.get()
                yield status, result
                if eof:
                    self.pending_command_ids.get()
                    break
        finally:
            try:
                self.clear_history_entry(command_id)
            except Exception:
                pass