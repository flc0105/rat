import threading
import uuid
from datetime import datetime


class WebTaskStore:
    """
    Web 任务状态存储。

    职责：
    - 创建任务记录
    - 追加任务输出分片
    - 标记任务完成状态
    - 提供任务查询能力（后续如需扩展）
    """

    def __init__(self):
        self._tasks = {}
        self._lock = threading.RLock()

    def create_task(self, client_id: str, command: str) -> dict:
        """
        创建任务记录
        """
        task_id = uuid.uuid4().hex
        task = {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'status': 'running',
            'created_at': datetime.now().isoformat(),
            'finished_at': None,
            'history_entry_id': '',
            'chunks': []
        }
        with self._lock:
            self._tasks[task_id] = task
        return task

    def append_chunk(self, task_id: str, status: int, text: str) -> None:
        """
        追加任务输出片段
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task['chunks'].append({
                'status': status,
                'text': text,
                'time': datetime.now().isoformat()
            })

    def finish_task(self, task_id: str, ok: bool) -> None:
        """
        标记任务完成
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task['status'] = 'success' if ok else 'error'
            task['finished_at'] = datetime.now().isoformat()

    def get_task(self, task_id: str):
        """
        获取任务信息
        """
        with self._lock:
            return self._tasks.get(task_id)

    def all_tasks(self):
        """
        返回任务快照
        """
        with self._lock:
            return dict(self._tasks)