import threading


class HistoryBindingStore:
    """
    command_id -> history entry_id 绑定存储。

    职责：
    - 绑定执行记录
    - 查询执行记录
    - 清理执行记录
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._entry_ids_by_command_id = {}

    def bind(self, command_id: int, entry_id: str):
        if not command_id or not entry_id:
            return

        with self._lock:
            self._entry_ids_by_command_id[command_id] = entry_id

    def get(self, command_id: int) -> str:
        with self._lock:
            return self._entry_ids_by_command_id.get(command_id, '')

    def clear(self, command_id: int):
        with self._lock:
            self._entry_ids_by_command_id.pop(command_id, None)








