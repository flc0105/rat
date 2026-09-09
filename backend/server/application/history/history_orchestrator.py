from server.application.history.history_record_policy import CommandHistoryRecordPolicy


class CommandHistoryOrchestrator:
    """
    命令历史编排器。

    职责：
    - 统一决定一条命令是否应该进入历史
    - 统一创建 history entry
    - 统一追加输出
    - 统一结束/收尾执行状态
    - 统一管理 command_id <-> history_entry_id 绑定
    - 统一处理 artifact 回挂到 history entry

    当前目标：
    - CLI / WebTask / RemoteExecution 的 history 写入走单入口
    - session runtime 只保留绑定存储，不再承担编排职责
    - web/app.py 不再自己拼 artifact 反向绑定逻辑
    """

    def __init__(self, history_store):
        self.history_store = history_store

    # ------------------ record policy ------------------ #
    def should_record_command(self, command: str, *, source: str = '', task_type: str = '') -> bool:
        """
        判断命令是否应该进入历史。
        统一委托给集中策略，避免规则散落在 CLI / Web / job / file / process 各入口。
        """
        return CommandHistoryRecordPolicy.should_record_command(
            command,
            source=source,
            task_type=task_type,
        )

    # ------------------ history entry lifecycle ------------------ #
    def begin_execution(self, conn, command: str, source: str = 'cli', should_record=None, task_type: str = '') -> str:
        """
        为一次执行创建 history entry。
        """
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        if should_record is None:
            should_record = self.should_record_command(
                command_text,
                source=source,
                task_type=task_type,
            )

        if not should_record:
            return ''

        return self.history_store.create_entry_for_connection(
            conn,
            command_text,
            source=source
        )

    def append_output(self, conn, entry_id: str, status: int, text: str, eof: int = 0):
        """
        为指定 history entry 追加输出。
        """
        if conn is None or not entry_id:
            return

        self.history_store.append_output_for_connection(
            conn,
            entry_id,
            status,
            text,
            eof
        )

    def discard_execution(self, conn, entry_id: str) -> bool:
        """
        丢弃尚未真正进入执行阶段的 history entry。
        """
        if conn is None or not entry_id:
            return False
        return self.history_store.write_service.delete_execution_entry_for_connection(conn, entry_id)

    def finalize_execution(self, conn, entry_id: str, ok: bool, cwd_end: str = ''):
        """
        统一结束一次执行历史。
        """
        if conn is None or not entry_id:
            return

        final_cwd = cwd_end or getattr(getattr(conn, 'session_info', None), 'cwd', '')
        self.history_store.update_entry_status_for_connection(
            conn,
            entry_id,
            'success' if ok else 'error',
            cwd_end=final_cwd
        )

    # ------------------ binding orchestration ------------------ #
    def bind_command_entry(self, conn, command_id: int, entry_id: str):
        """
        绑定 command_id -> history_entry_id。
        """
        if conn is None or not command_id or not entry_id:
            return

        try:
            conn.bind_history_entry(command_id, entry_id)
        except Exception:
            pass

    def get_bound_entry_id(self, conn, command_id: int) -> str:
        """
        获取 command_id 当前绑定的 history_entry_id。
        """
        if conn is None or not command_id:
            return ''

        try:
            return conn.get_history_entry_id(command_id)
        except Exception:
            return ''

    def clear_command_entry(self, conn, command_id: int):
        """
        清理 command_id -> history_entry_id 绑定。
        """
        if conn is None or not command_id:
            return

        try:
            conn.clear_history_entry(command_id)
        except Exception:
            pass

    # ------------------ artifact binding ------------------ #
    def bind_uploaded_artifact(self, conn, source_command_id, artifact: dict) -> bool:
        """
        将 HTTP 上传产生的 artifact 挂回到对应的 history entry。
        """
        if conn is None:
            return False

        if source_command_id is None:
            return False

        if not isinstance(artifact, dict) or not artifact:
            return False

        entry_id = self.get_bound_entry_id(conn, source_command_id)
        if not entry_id:
            return False

        self.history_store.append_file_for_connection(
            conn,
            entry_id,
            artifact
        )
        return True








