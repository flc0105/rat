import threading


class ForegroundTaskGuard:
    """
    前台执行槽守卫。

    职责：
    - 管理当前连接的前台占用任务
    - 提供 acquire / release / snapshot
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._task = None

    def acquire(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        task_info = {
            'task_type': task_type,
            'command': (command or '').strip(),
            'source': (source or '').strip(),
            'task_id': (task_id or '').strip(),
            'command_id': None,
            'cancel_requested': False,
        }

        with self._lock:
            if self._task is not None:
                current = self._task
                raise RuntimeError(
                    'Client is busy: '
                    f'{current.get("command") or current.get("task_type") or "running task"}'
                )

            self._task = task_info
            return dict(task_info)

    def bind_command_id(self, command_id: int):
        with self._lock:
            if self._task is None:
                return None

            self._task['command_id'] = command_id
            return dict(self._task)

    def request_cancel(self, task_id: str = ''):
        task_id = (task_id or '').strip()

        with self._lock:
            if self._task is None:
                return None

            if task_id and self._task.get('task_id') and self._task.get('task_id') != task_id:
                return None

            self._task['cancel_requested'] = True
            return dict(self._task)

    def release(self, task_id: str = '', command: str = '') -> None:
        task_id = (task_id or '').strip()
        command = (command or '').strip()

        with self._lock:
            if self._task is None:
                return

            current = self._task

            if task_id and current.get('task_id') and current.get('task_id') != task_id:
                return

            if command and current.get('command') and current.get('command') != command:
                return

            self._task = None

    def snapshot(self):
        with self._lock:
            if self._task is None:
                return None
            return dict(self._task)
