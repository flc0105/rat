class ForegroundTaskCoordinator:
    """
    前台任务协调器。

    职责：
    - 统一占用当前连接的前台执行槽
    - 校验任务是否仍是当前前台任务
    - 发起前台任务取消请求
    - 统一释放前台任务槽

    说明：
    - 这里只收口与 foreground task 相关的连接运行态操作
    - 不负责 task store 的状态推进
    """

    def acquire_command_task(self, conn, task_id: str, command: str, source: str = 'web'):
        return conn.acquire_foreground_task(
            task_type='command',
            command=command,
            source=source,
            task_id=task_id,
        )

    def acquire_upload_task(self, conn, task_id: str, command: str, source: str = 'web'):
        return conn.acquire_foreground_task(
            task_type='upload',
            command=command,
            source=source,
            task_id=task_id,
        )

    def ensure_active_task(self, conn, task_id: str):
        foreground_task = conn.get_foreground_task() or {}
        current_task_id = (foreground_task.get('task_id') or '').strip()
        if current_task_id != str(task_id).strip():
            raise ValueError('task is no longer the active foreground task')
        return foreground_task

    def request_cancel(self, conn, task_id: str):
        self.ensure_active_task(conn, task_id)

        cancel_info = conn.request_foreground_task_cancel(task_id=task_id)
        if not cancel_info:
            raise RuntimeError('failed to request task cancellation')

        command_id = cancel_info.get('command_id')
        if command_id:
            conn.send_cancel(command_id)

        return cancel_info

    def release_task(self, conn, task_id: str = '', command: str = '') -> None:
        conn.release_foreground_task(task_id=task_id, command=command)