import os
import shutil

from server.application.command.executor import CommandExecutor
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.application.tasks.task_event_publisher import WebTaskEventPublisher
from server.application.tasks.task_history_recorder import WebTaskHistoryRecorder
from server.application.tasks.task_stream_orchestrator import WebTaskStreamOrchestrator


class WebTaskRunner:
    """
    Web 任务执行器。

    职责：
    - 消费命令 / 上传结果流
    - 写 task chunks
    - 推送 SSE
    - 写 history
    - 统一结束收尾

    新增：
    - 按 task.tab_id 定向推送前台命令结果

    当前进一步拆分：
    - 结果事件发布：WebTaskEventPublisher
    - history 记录：WebTaskHistoryRecorder
    - stream 生命周期编排：WebTaskStreamOrchestrator
    """

    def __init__(self, server, event_bus, task_store):
        self.server = server
        self.event_bus = event_bus
        self.task_store = task_store
        self.remote_execution_service = RemoteExecutionService(server)
        self.history_orchestrator = self.server.command_history_orchestrator

        self.event_publisher = WebTaskEventPublisher(
            event_bus=self.event_bus,
            task_store=self.task_store,
        )
        self.history_recorder = WebTaskHistoryRecorder(
            history_orchestrator=self.history_orchestrator,
            task_store=self.task_store,
        )
        self.stream_orchestrator = WebTaskStreamOrchestrator(
            task_store=self.task_store,
            event_publisher=self.event_publisher,
            history_recorder=self.history_recorder,
        )

    # ------------------ command ------------------ #
    def run_command_task(self, conn, task_id: str, command: str):
        try:
            def _result_iter():
                task = self.task_store.get_task(task_id) or {}
                history_entry_id = task.get('history_entry_id') or ''

                executor = CommandExecutor(conn, self.server)
                func = executor.process_command(command, history_entry_id=history_entry_id)
                if not func:
                    raise RuntimeError('Unable to resolve command')
                yield from func()

            self.stream_orchestrator.run_stream(conn, task_id, command, _result_iter())
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

    # ------------------ upload ------------------ #
    def run_upload_task(self, conn, task_id: str, local_path: str, display_name: str, remote_path: str = '', upload_tmp_dir: str = ''):
        command = f'upload {display_name}'

        try:
            task = self.task_store.get_task(task_id) or {}
            history_entry_id = task.get('history_entry_id') or ''

            self.stream_orchestrator.run_stream(
                conn,
                task_id,
                command,
                self.remote_execution_service.stream_upload(
                    conn,
                    local_path,
                    remote_path=remote_path,
                    history_entry_id=history_entry_id
                )
            )
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
                parent_dir = os.path.dirname(local_path)
                if upload_tmp_dir and parent_dir.startswith(upload_tmp_dir) and os.path.isdir(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass


