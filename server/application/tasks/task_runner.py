import os
import shutil
from datetime import datetime

from server.application.command.command_execution_pipeline import CommandExecutionPipeline
from server.application.tasks.task_status import TaskStreamSummary, WebTaskStatus


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
    """

    def __init__(self, server, event_bus, task_store, remote_execution_service, command_executor_factory):
        self.server = server
        self.event_bus = event_bus
        self.task_store = task_store
        self.remote_execution_service = remote_execution_service
        self.command_executor_factory = command_executor_factory
        self.history_orchestrator = self.server.command_history_orchestrator
        # add web命令执行链并入统一pipeline 2026-04-09
        self.command_execution_pipeline = CommandExecutionPipeline(
            command_history_orchestrator=self.history_orchestrator,
            output_writer=lambda *_: None,
        )

    def _get_task(self, task_id: str) -> dict:
        return self.task_store.get_task(task_id) or {}

    def _get_history_entry_id(self, task_id: str) -> str:
        task = self._get_task(task_id)
        return task.get('history_entry_id') or ''

    def _get_task_tab_id(self, task_id: str) -> str:
        task = self._get_task(task_id)
        return (task.get('tab_id') or '').strip()

    def _append_history_output(self, conn, task_id: str, status: int, text: str):
        history_entry_id = self._get_history_entry_id(task_id)
        self.history_orchestrator.append_output(
            conn,
            history_entry_id,
            status,
            text,
            0
        )

    def _finalize_history(self, conn, task_id: str, final_status: str):
        history_entry_id = self._get_history_entry_id(task_id)
        self.history_orchestrator.finalize_execution(
            conn,
            history_entry_id,
            final_status == WebTaskStatus.SUCCESS,
            cwd_end=conn.session_info.cwd
        )

    def _publish_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
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

    def _publish_task_complete(self, task_id: str, client_id: str, command: str):
        target_tab_id = self._get_task_tab_id(task_id)
        task = self._get_task(task_id)
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

    def _publish_stream_chunk(self, conn, task_id: str, client_id: str, command: str, status: int, text: str):
        self._publish_task_result(
            task_id,
            client_id,
            command,
            status,
            text
        )
        self._append_history_output(conn, task_id, status, text)

    def _resolve_final_status(self, task_id: str, summary: TaskStreamSummary) -> str:
        task = self._get_task(task_id)
        return summary.resolve_final_status(
            cancel_requested=bool(task.get('cancel_requested'))
        )

    def _finalize_stream(self, conn, task_id: str, client_id: str, command: str, final_status: str, summary: TaskStreamSummary):
        self.task_store.finish_task(
            task_id,
            ok=summary.is_success(),
            final_status=final_status
        )

        self._finalize_history(
            conn,
            task_id,
            final_status=final_status
        )

        self._publish_task_complete(
            task_id,
            client_id,
            command
        )

    def _run_stream(self, conn, task_id: str, command: str, result_iter):
        """
        统一执行 Web 任务结果流：
        - 消费生成器输出
        - 记录任务分片
        - 推送 SSE 结果
        - 统一异常处理
        - 统一结束收尾
        """
        client_id = conn.session_info.client_id
        summary = TaskStreamSummary()

        try:
            for status, result in result_iter:
                text = '' if result is None else str(result)
                self._publish_stream_chunk(conn, task_id, client_id, command, status, text)
                summary.record_chunk(status, text)

        except Exception as e:
            text = str(e)
            summary.mark_exception()
            self._publish_stream_chunk(conn, task_id, client_id, command, 0, text)

        finally:
            final_status = self._resolve_final_status(task_id, summary)
            self._finalize_stream(conn, task_id, client_id, command, final_status, summary)

    # add web命令执行chunk回调 2026-04-09
    def _build_command_output_writer(self, conn, task_id: str, command: str, summary: TaskStreamSummary):
        client_id = conn.session_info.client_id

        def writer(status: int, result):
            text = '' if result is None else str(result)
            self._publish_stream_chunk(conn, task_id, client_id, command, status, text)
            summary.record_chunk(status, text)

        return writer

    # add web命令执行统一pipeline入口 2026-04-09
    def _run_command_pipeline(self, conn, task_id: str, command: str):
        history_entry_id = self._get_history_entry_id(task_id)
        executor = self.command_executor_factory.create(conn)
        summary = TaskStreamSummary()

        self.command_execution_pipeline.execute_bound(
            conn,
            executor,
            command,
            history_entry_id=history_entry_id,
            output_writer=self._build_command_output_writer(conn, task_id, command, summary),
            finalize_history=False,
            swallow_exception=True,
        )

        final_status = self._resolve_final_status(task_id, summary)
        self._finalize_stream(
            conn,
            task_id,
            conn.session_info.client_id,
            command,
            final_status,
            summary,
        )

    def _build_upload_result_iter(
        self,
        conn,
        task_id: str,
        local_path: str,
        remote_path: str = '',
    ):
        history_entry_id = self._get_history_entry_id(task_id)
        return self.remote_execution_service.stream_upload(
            conn,
            local_path,
            remote_path=remote_path,
            history_entry_id=history_entry_id,
        )

    def _release_task(self, conn, task_id: str = '', command: str = '') -> None:
        conn.release_foreground_task(task_id=task_id, command=command)

    # ------------------ command ------------------ #
    def run_command_task(self, conn, task_id: str, command: str):
        try:
            self._run_command_pipeline(conn, task_id, command)
        finally:
            self._release_task(conn, task_id=task_id, command=command)

    # ------------------ upload ------------------ #
    def run_upload_task(self, conn, task_id: str, local_path: str, display_name: str, remote_path: str = '', upload_tmp_dir: str = ''):
        command = f'upload {display_name}'

        try:
            self._run_stream(
                conn,
                task_id,
                command,
                self._build_upload_result_iter(
                    conn,
                    task_id,
                    local_path,
                    remote_path=remote_path,
                ),
            )
        finally:
            self._release_task(conn, task_id=task_id, command=command)

            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
                parent_dir = os.path.dirname(local_path)
                if upload_tmp_dir and parent_dir.startswith(upload_tmp_dir) and os.path.isdir(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass