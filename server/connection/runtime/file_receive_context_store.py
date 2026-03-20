import threading

from server.models.artifact import FileReceiveContext


class FileReceiveContextStore:
    """
    文件接收上下文存储。

    职责：
    - 为指定 command_id 保存 file receive context
    - 在接收完成时弹出上下文
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._contexts = {}

    def set(self, command_id: int, **context):
        with self._lock:
            self._contexts[command_id] = FileReceiveContext.from_dict(context)

    def pop(self, command_id: int):
        with self._lock:
            context = self._contexts.pop(command_id, None)

        if isinstance(context, FileReceiveContext):
            return context
        return FileReceiveContext.from_dict(context)