from datetime import datetime

from server.connection.client_connection import ClientConnection


class WebTaskRunner:
    """
    Web 任务执行编排器。

    职责：
    - 消费任务结果流
    - 写入 task_store
    - 推送 SSE 结果/完成事件
    - 追加 command history 输出
    - 标记任务完成状态
    - 更新 command history 最终状态
    """

    def __init__(self, server, event_bus, task_store):
        self.server = server
        self.event_bus = event_bus
        self.task_store = task_store

    # ------------------ publish helpers ------------------ #
    def publish_task_result(self, task_id: str, client_id: str, command: str, status: int, text: str):
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

    def publish_task_complete(self, task_id: str, client_id: str, command: str, ok: bool):
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

    # ------------------ history helpers ------------------ #
    def _get_task_history_entry_id(self, task_id: str) -> str:
        task = self.task_store.get_task(task_id) or {}
        return task.get('history_entry_id') or ''

    def _append_history_output(self, conn: ClientConnection, task_id: str, status: int, text: str):
        history_entry_id = self._get_task_history_entry_id(task_id)
        if not history_entry_id:
            return

        self.server.command_history.append_output_for_connection(
            conn,
            history_entry_id,
            status,
            text,
            0
        )

    def _finish_history_entry(self, conn: ClientConnection, task_id: str, ok: bool):
        history_entry_id = self._get_task_history_entry_id(task_id)
        if not history_entry_id:
            return

        self.server.command_history.update_entry_status_for_connection(
            conn,
            history_entry_id,
            'success' if ok else 'error',
            cwd_end=conn.info.get('cwd', '')
        )

    # ------------------ main runner ------------------ #
    def run_task_stream(self, conn: ClientConnection, task_id: str, command: str, result_iter):
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

        try:
            for status, result in result_iter:
                text = '' if result is None else str(result)

                self.publish_task_result(task_id, client_id, command, status, text)
                self._append_history_output(conn, task_id, status, text)

                if status == 0:
                    ok = False

        except Exception as e:
            ok = False
            text = str(e)

            self.publish_task_result(task_id, client_id, command, 0, text)
            self._append_history_output(conn, task_id, 0, text)

        finally:
            self.task_store.finish_task(task_id, ok)
            self._finish_history_entry(conn, task_id, ok)
            self.publish_task_complete(task_id, client_id, command, ok)