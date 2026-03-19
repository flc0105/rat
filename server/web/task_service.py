import os
import shutil
import threading

from server.commands.executor import CommandExecutor
from server.connection.client_connection import ClientConnection


class WebTaskService:
    """
    Web 任务服务。

    职责：
    - 提交并启动 Web 命令 / 上传任务
    - 管理前台占用与线程启动
    - 将具体执行流程交给 task_runner
    """

    def __init__(self, server, task_store, file_service, task_runner):
        self.server = server
        self.task_store = task_store
        self.file_service = file_service
        self.task_runner = task_runner

    # ------------------ web command ------------------ #
    def submit_web_command(self, client_id: str, command: str):
        conn = self.server.get_target_connection_by_client_id(client_id)

        command_text = (command or '').strip()
        should_record = (
            bool(command_text)
            and not command_text.startswith('history')
        )

        entry_id = ''
        if should_record:
            entry_id = self.server.command_history.create_entry_for_connection(conn, command, source='web')

        task = self.task_store.create_task(client_id, command)
        task['history_entry_id'] = entry_id

        conn.acquire_foreground_task(
            task_type='command',
            command=command,
            source='web',
            task_id=task['task_id']
        )

        threading.Thread(
            target=self._run_web_command,
            args=(conn, task['task_id'], command),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def _run_web_command(self, conn: ClientConnection, task_id: str, command: str):
        try:
            def _result_iter():
                task = self.task_store.get_task(task_id) or {}
                history_entry_id = task.get('history_entry_id') or ''

                executor = CommandExecutor(conn, self.server)
                func = executor.process_command(command, history_entry_id=history_entry_id)
                if not func:
                    raise RuntimeError('Unable to resolve command')
                yield from func()

            self.task_runner.run_task_stream(conn, task_id, command, _result_iter())
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

    # ------------------ web upload ------------------ #
    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)
        command = f'upload {display_name}'

        entry_id = self.server.command_history.create_entry_for_connection(conn, command, source='web')
        task = self.task_store.create_task(client_id, command)
        task['history_entry_id'] = entry_id

        conn.acquire_foreground_task(
            task_type='upload',
            command=command,
            source='web',
            task_id=task['task_id']
        )

        threading.Thread(
            target=self._run_web_upload,
            args=(conn, task['task_id'], local_path, display_name, remote_path),
            daemon=True
        ).start()

        return {
            'task_id': task['task_id'],
            'client_id': client_id,
            'command': command
        }

    def _run_web_upload(self, conn: ClientConnection, task_id: str, local_path: str, display_name: str,
                        remote_path: str = ''):
        command = f'upload {display_name}'

        try:
            task = self.task_store.get_task(task_id) or {}
            history_entry_id = task.get('history_entry_id') or ''

            self.task_runner.run_task_stream(
                conn,
                task_id,
                command,
                conn.send_file(local_path, save_dir=remote_path, history_entry_id=history_entry_id)
            )
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
                parent_dir = os.path.dirname(local_path)
                if parent_dir.startswith(self.file_service.upload_tmp_dir) and os.path.isdir(parent_dir):
                    shutil.rmtree(parent_dir, ignore_errors=True)
            except Exception:
                pass