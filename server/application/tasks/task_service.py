import threading

from server.application.execution.execution_context import TaskExecutionContext
from server.application.tasks.task_types import TASK_TYPE_COMMAND, TASK_TYPE_UPLOAD


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
        self.history_orchestrator = self.server.command_history_orchestrator

    def _create_task_with_history(
        self,
        conn,
        client_id: str,
        command: str,
        *,
        tab_id: str = '',
        source: str = 'web',
        should_record=None,
    ):
        entry_id = self.history_orchestrator.begin_execution(
            conn,
            command,
            source=source,
            should_record=should_record,
        )

        task = self.task_store.create_task(client_id, command, tab_id=tab_id)
        task['history_entry_id'] = entry_id
        return task

    def _build_task_context(self, conn, task: dict, command: str, *, task_type: str, source: str = 'web') -> TaskExecutionContext:
        return TaskExecutionContext.from_task(
            conn,
            task,
            command,
            source=source,
            task_type=task_type,
        )

    def _start_task_thread(self, target, *args):
        threading.Thread(
            target=target,
            args=args,
            daemon=True,
        ).start()

    def _acquire_task(self, context: TaskExecutionContext):
        return context.session.acquire_foreground_task(
            task_type=context.task_type,
            command=context.command,
            source=context.source,
            task_id=context.task_id,
            history_entry_id=context.history_entry_id,
        )

    def _ensure_active_task(self, conn, task_id: str):
        foreground_task = conn.get_foreground_task() or {}
        current_task_id = (foreground_task.get('task_id') or '').strip()
        if current_task_id != str(task_id).strip():
            raise ValueError('task is no longer the active foreground task')
        return foreground_task

    def _request_task_cancel(self, conn, task_id: str):
        self.task_store.request_cancel(task_id)
        foreground_task = self._ensure_active_task(conn, task_id)

        cancel_info = conn.request_foreground_task_cancel(task_id=task_id)
        if not cancel_info:
            raise RuntimeError('failed to request task cancellation')

        command_id = cancel_info.get('command_id')
        if command_id:
            conn.send_cancel(command_id)

        result = dict(cancel_info)
        if not result.get('history_entry_id'):
            result['history_entry_id'] = foreground_task.get('history_entry_id') or ''
        return result

    def _resolve_cancellable_task(self, task_id: str):
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
        self._ensure_active_task(conn, task_id)
        return task, conn

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)

        task = self._create_task_with_history(
            conn,
            client_id,
            command,
            tab_id=tab_id,
            source='web',
        )

        context = self._build_task_context(
            conn,
            task,
            command,
            task_type=TASK_TYPE_COMMAND,
            source='web',
        )

        self._acquire_task(context)
        self._start_task_thread(self.task_runner.run_command_task, context)

        return {
            'task_id': context.task_id,
            'client_id': client_id,
            'command': command,
        }

    def cancel_web_task(self, task_id: str):
        task, conn = self._resolve_cancellable_task(task_id)
        client_id = task.get('client_id') or ''
        cancel_info = self._request_task_cancel(conn, task_id)
        command_id = cancel_info.get('command_id')

        return {
            'task_id': task_id,
            'client_id': client_id,
            'status': 'cancelling',
            'command_id': command_id,
            'history_entry_id': cancel_info.get('history_entry_id') or '',
        }

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)
        command = f'upload {display_name}'

        task = self._create_task_with_history(
            conn,
            client_id,
            command,
            tab_id=tab_id,
            source='web',
            should_record=True,
        )

        context = self._build_task_context(
            conn,
            task,
            command,
            task_type=TASK_TYPE_UPLOAD,
            source='web',
        )
        context.metadata['local_path'] = local_path
        context.metadata['display_name'] = display_name
        context.metadata['remote_path'] = remote_path
        context.metadata['upload_tmp_dir'] = getattr(self.file_service, 'upload_tmp_dir', '')

        self._acquire_task(context)
        self._start_task_thread(self.task_runner.run_upload_task, context)

        return {
            'task_id': context.task_id,
            'client_id': client_id,
            'command': command,
        }