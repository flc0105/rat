import threading

from server.application.execution.remote_execution_service import RemoteExecutionService


class WebTaskService:
    """
    Web 任务服务。

    职责：
    - 提交并登记 Web 命令 / 上传任务
    - 占用前台执行槽
    - 启动 runner 真正执行
    """

    def __init__(self, server, task_store, file_service, task_runner):
        self.server = server
        self.task_store = task_store
        self.file_service = file_service
        self.task_runner = task_runner
        self.remote_execution_service = RemoteExecutionService(server)
        self.history_orchestrator = self.server.command_history_orchestrator

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)

        entry_id = self.history_orchestrator.begin_execution(
            conn,
            command,
            source='web'
        )

        task = self.task_store.create_task(client_id, command, tab_id=tab_id)
        task['history_entry_id'] = entry_id

        conn.acquire_foreground_task(
            task_type='command',
            command=command,
            source='web',
            task_id=task['task_id']
        )

        threading.Thread(
            target=self.task_runner.run_command_task,
            args=(conn, task['task_id'], command),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def cancel_web_task(self, task_id: str):
        task = self.task_store.get_task(task_id)
        if not task:
            raise ValueError('task not found')

        task_status = str(task.get('status') or '').strip()
        if task_status not in ('running', 'cancelling'):
            raise ValueError(f'task is not cancellable: {task_status or "unknown"}')

        client_id = task.get('client_id') or ''
        if not client_id:
            raise ValueError('task client_id is missing')

        conn = self.server.get_target_connection_by_client_id(client_id)
        foreground_task = conn.get_foreground_task() or {}

        current_task_id = (foreground_task.get('task_id') or '').strip()
        if current_task_id != str(task_id).strip():
            raise ValueError('task is no longer the active foreground task')

        self.task_store.request_cancel(task_id)

        cancel_info = conn.request_foreground_task_cancel(task_id=task_id)
        if not cancel_info:
            raise RuntimeError('failed to request task cancellation')

        command_id = cancel_info.get('command_id')
        if command_id:
            conn.send_cancel(command_id)

        return {
            'task_id': task_id,
            'client_id': client_id,
            'status': 'cancelling',
            'command_id': command_id,
        }

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)
        command = f'upload {display_name}'

        entry_id = self.history_orchestrator.begin_execution(
            conn,
            command,
            source='web',
            should_record=True
        )

        task = self.task_store.create_task(client_id, command, tab_id=tab_id)
        task['history_entry_id'] = entry_id

        conn.acquire_foreground_task(
            task_type='upload',
            command=command,
            source='web',
            task_id=task['task_id']
        )

        threading.Thread(
            target=self.task_runner.run_upload_task,
            args=(
                conn,
                task['task_id'],
                local_path,
                display_name,
                remote_path,
                getattr(self.file_service, 'upload_tmp_dir', '')
            ),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }



