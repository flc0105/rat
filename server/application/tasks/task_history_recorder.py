class WebTaskHistoryRecorder:
    """
    Web 任务历史记录器。

    职责：
    - 将任务结果流写入 command history
    - 在任务结束时统一 finalize execution
    """

    def __init__(self, history_orchestrator, task_store):
        self.history_orchestrator = history_orchestrator
        self.task_store = task_store

    def _get_history_entry_id(self, task_id: str) -> str:
        task = self.task_store.get_task(task_id) or {}
        return task.get('history_entry_id') or ''

    def append_output(self, conn, task_id: str, status: int, text: str):
        history_entry_id = self._get_history_entry_id(task_id)
        self.history_orchestrator.append_output(
            conn,
            history_entry_id,
            status,
            text,
            0
        )

    def finalize(self, conn, task_id: str, ok: bool):
        history_entry_id = self._get_history_entry_id(task_id)
        self.history_orchestrator.finalize_execution(
            conn,
            history_entry_id,
            ok,
            cwd_end=conn.info.get('cwd', '')
        )