import os
import shutil
from datetime import datetime

from server.application.command.executor import CommandExecutor
from server.application.execution.remote_execution_service import RemoteExecutionService


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

    def __init__(self, server, event_bus, task_store):
        self.server = server
        self.event_bus = event_bus
        self.task_store = task_store
        self.remote_execution_service = RemoteExecutionService(server)

    def _get_task_tab_id(self, task_id: str) -> str:
        task = self.task_store.get_task(task_id) or {}
        return (task.get('tab_id') or '').strip()

    # ------------------ task event publish ------------------ #
    def _publish_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
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

    def _publish_task_complete(self, task_id: str, client_id: str, command: str, ok: bool):
        """
        发布 Web 任务完成事件
        """
        target_tab_id = self._get_task_tab_id(task_id)

        self.event_bus.publish(
            'command_complete',
            {
                'task_id': task_id,
                'client_id': client_id,
                'command': command,
                'success': ok,
                'time': datetime.now().isoformat()
            },
            target_tab_id=target_tab_id
        )

    # ------------------ core stream runner ------------------ #
    def _run_task_stream(self, conn, task_id: str, command: str, result_iter):
        """
        统一执行 Web 任务结果流：
        - 消费生成器输出
        - 记录任务分片
        - 推送 SSE 结果
        - 统一异常处理
        - 统一结束收尾
        """
        client_id = conn.info.get('id')
        ok = True

        task = self.task_store.get_task(task_id) or {}
        history_entry_id = task.get('history_entry_id') or ''

        try:
            for status, result in result_iter:
                text = '' if result is None else str(result)
                self._publish_task_result(task_id, client_id, command, status, text)

                if history_entry_id:
                    self.remote_execution_service.append_history_output(
                        conn,
                        history_entry_id,
                        status,
                        text,
                        0
                    )

                if status == 0:
                    ok = False

        except Exception as e:
            ok = False
            text = str(e)
            self._publish_task_result(task_id, client_id, command, 0, text)

            if history_entry_id:
                self.remote_execution_service.append_history_output(
                    conn,
                    history_entry_id,
                    0,
                    text,
                    0
                )

        finally:
            self.task_store.finish_task(task_id, ok)

            if history_entry_id:
                self.remote_execution_service.finalize_history_entry(
                    conn,
                    history_entry_id,
                    ok,
                    cwd_end=conn.info.get('cwd', '')
                )

            self._publish_task_complete(task_id, client_id, command, ok)

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

            self._run_task_stream(conn, task_id, command, _result_iter())
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

    # ------------------ upload ------------------ #
    def run_upload_task(self, conn, task_id: str, local_path: str, display_name: str, remote_path: str = '', upload_tmp_dir: str = ''):
        command = f'upload {display_name}'

        try:
            task = self.task_store.get_task(task_id) or {}
            history_entry_id = task.get('history_entry_id') or ''

            self._run_task_stream(
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