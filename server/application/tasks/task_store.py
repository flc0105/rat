import threading
import uuid
from datetime import datetime

from server.application.tasks.task_status import WebTaskStatus


class WebTaskStore:
    """
    Web 任务状态存储。

    职责：
    - 创建任务记录
    - 追加任务输出分片
    - 标记任务完成状态
    - 提供任务查询能力（后续如需扩展）

    新增：
    - tab_id：记录发起当前任务的浏览器页签
    """

    def __init__(self):
        self._tasks = {}
        self._lock = threading.RLock()

    def create_task(self, client_id: str, command: str, tab_id: str = '') -> dict:
        """
        创建任务记录
        """
        task_id = uuid.uuid4().hex
        task = {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'tab_id': (tab_id or '').strip(),
            'status': WebTaskStatus.RUNNING,
            'cancel_requested': False,
            'created_at': datetime.now().isoformat(),
            'finished_at': None,
            'history_entry_id': '',
            'chunks': []
        }
        with self._lock:
            self._tasks[task_id] = task
        return task

    def request_cancel(self, task_id: str) -> dict | None:
        """
        请求取消任务
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None

            task['cancel_requested'] = True
            if task.get('status') == WebTaskStatus.RUNNING:
                task['status'] = WebTaskStatus.CANCELLING
            return dict(task)

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

    def _task_has_cancelled_output(self, task: dict) -> bool:
        for chunk in reversed(task.get('chunks') or []):
            text = str(chunk.get('text') or '').strip().lower()
            if not text:
                continue
            if 'cancelled' in text or 'timed out and was terminated' in text:
                return True
            return False
        return False

    def finish_task(self, task_id: str, ok: bool, final_status: str = '') -> None:
        """
        标记任务完成
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return

            normalized_final_status = str(final_status or '').strip()
            if normalized_final_status in WebTaskStatus.TERMINAL_STATUSES:
                task['status'] = normalized_final_status
            else:
                if task.get('cancel_requested') and self._task_has_cancelled_output(task):
                    task['status'] = WebTaskStatus.CANCELLED
                else:
                    task['status'] = WebTaskStatus.SUCCESS if ok else WebTaskStatus.ERROR

            task['finished_at'] = datetime.now().isoformat()

    def is_task_cancelled(self, task_id: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            return task.get('status') == WebTaskStatus.CANCELLED

    def get_task(self, task_id: str):
        """
        获取任务信息
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            return dict(task)

    def all_tasks(self):
        """
        返回任务快照
        """
        with self._lock:
            return dict(self._tasks)


