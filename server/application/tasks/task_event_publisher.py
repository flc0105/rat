from datetime import datetime

from server.application.tasks.task_status import WebTaskStatus


class WebTaskEventPublisher:
    """
    Web 任务事件发布器。

    职责：
    - 发布 command_result
    - 发布 command_complete
    - 根据 task.tab_id 做定向 SSE 推送
    """

    def __init__(self, event_bus, task_store):
        self.event_bus = event_bus
        self.task_store = task_store

    def _get_task_tab_id(self, task_id: str) -> str:
        task = self.task_store.get_task(task_id) or {}
        return (task.get('tab_id') or '').strip()

    def publish_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
        """
        发布 Web 任务执行中的单条结果，并写入任务记录
        """
        self.task_store.append_chunk(task_id, status, text)
        target_tab_id = self._get_task_tab_id(task_id)

        self.event_bus.publish(
            'command_result',
            {
                'task_id': task_id,
                'client_id': client_id,
                'command': command,
                'status': status,
                'text': text,
                'time': datetime.now().isoformat()
            },
            target_tab_id=target_tab_id
        )

    def publish_task_complete(self, task_id: str, client_id: str, command: str):
        """
        发布 Web 任务完成事件
        """
        target_tab_id = self._get_task_tab_id(task_id)
        task = self.task_store.get_task(task_id) or {}
        task_status = task.get('status') or WebTaskStatus.ERROR

        self.event_bus.publish(
            'command_complete',
            {
                'task_id': task_id,
                'client_id': client_id,
                'command': command,
                'success': task_status == WebTaskStatus.SUCCESS,
                'status': task_status,
                'cancel_requested': bool(task.get('cancel_requested')),
                'cancelled': task_status == WebTaskStatus.CANCELLED,
                'time': datetime.now().isoformat()
            },
            target_tab_id=target_tab_id
        )





