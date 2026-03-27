from typing import Optional

from core.protocol.message_queue import MessageQueue, PendingCommandQueue
from server.connection.runtime.foreground_task_guard import ForegroundTaskGuard
from server.connection.runtime.history_binding_store import HistoryBindingStore


class ClientSessionRuntime:
    """
    客户端会话运行时。

    职责：
    - 保存与本次连接会话相关的运行状态
    - 不直接负责 socket 收发
    - 为 ClientSession / CommandChannel 提供运行态存取能力

    当前承载：
    - pending_command_ids
    - message_queue
    - foreground_task_guard
    - history_binding_store
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

    # ------------------ foreground task ------------------ #
    def acquire_foreground_task(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        """
        尝试占用当前连接的前台执行槽。
        """
        return self._foreground_task_guard.acquire(
            task_type=task_type,
            command=command,
            source=source,
            task_id=task_id,
        )

    def bind_foreground_command_id(self, command_id: int):
        """
        将实际下发的 command_id 绑定到当前前台任务
        """
        return self._foreground_task_guard.bind_command_id(command_id)

    def request_foreground_task_cancel(self, task_id: str = ''):
        """
        请求取消当前前台任务
        """
        return self._foreground_task_guard.request_cancel(task_id=task_id)

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
                history_orchestrator = getattr(connection.context, 'command_history_orchestrator', None)
                if history_orchestrator is not None:
                    history_orchestrator.clear_command_entry(connection, command_id)
                else:
                    self.clear_history_entry(command_id)
            except Exception:
                pass
