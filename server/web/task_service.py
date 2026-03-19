import os
import shutil
import threading
from datetime import datetime

from server.commands.executor import CommandExecutor
from server.connection.client_connection import ClientConnection


class WebTaskService:
    """
    Web 任务服务。

    职责：
    - 提交并执行 Web 命令 / 上传任务
    - 管理任务状态
    - 推送任务过程 / 完成事件
    """

    def __init__(self, server, event_bus, task_store, file_service):
        self.server = server
        self.event_bus = event_bus
        self.task_store = task_store
        self.file_service = file_service

    # ------------------ task event publish ------------------ #
    def _publish_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
        """
        发布 Web 任务执行中的单条结果，并写入任务记录
        """
        self.task_store.append_chunk(task_id, status, text)

        self.event_bus.publish('command_result', {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'status': status,
            'text': text,
            'time': datetime.now().isoformat()
        })

    def _publish_task_complete(self, task_id: str, client_id: str, command: str, ok: bool):
        """
        发布 Web 任务完成事件
        """
        self.event_bus.publish('command_complete', {
            'task_id': task_id,
            'client_id': client_id,
            'command': command,
            'success': ok,
            'time': datetime.now().isoformat()
        })

    # ------------------ task execution ------------------ #
    def _run_task_stream(self, conn: ClientConnection, task_id: str, command: str, result_iter):
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
                    self.server.command_history.append_output_for_connection(
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
                self.server.command_history.append_output_for_connection(
                    conn,
                    history_entry_id,
                    0,
                    text,
                    0
                )

        finally:
            self.task_store.finish_task(task_id, ok)

            task = self.task_store.get_task(task_id) or {}
            history_entry_id = task.get('history_entry_id') or ''
            if history_entry_id:
                self.server.command_history.update_entry_status_for_connection(
                    conn,
                    history_entry_id,
                    'success' if ok else 'error',
                    cwd_end=conn.info.get('cwd', '')
                )

            self._publish_task_complete(task_id, client_id, command, ok)

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

        # client is busy start
        conn.acquire_foreground_task(
            task_type='command',
            command=command,
            source='web',
            task_id=task['task_id']
        )
        # client is busy end

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

            self._run_task_stream(conn, task_id, command, _result_iter())
        finally:
            conn.release_foreground_task(task_id=task_id, command=command)

    # ------------------ web upload ------------------ #
    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = ''):
        conn = self.server.get_target_connection_by_client_id(client_id)
        command = f'upload {display_name}'
        entry_id = self.server.command_history.create_entry_for_connection(conn, command, source='web')
        task = self.task_store.create_task(client_id, command)
        task['history_entry_id'] = entry_id

        # client is busy start
        conn.acquire_foreground_task(
            task_type='upload',
            command=command,
            source='web',
            task_id=task['task_id']
        )
        # client is busy end

        threading.Thread(
            target=self._run_web_upload,
            args=(conn, task['task_id'], local_path, display_name, remote_path), daemon=True
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

            self._run_task_stream(
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