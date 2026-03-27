class CommandHistoryOrchestrator:
    """
    命令历史编排器。

    职责：
    - 统一决定一条命令是否应该进入历史
    - 统一创建 history entry
    - 统一追加输出
    - 统一结束/收尾执行状态
    - 作为服务端 history 写入的单入口 orchestration

    当前先收口：
    - CLI 交互执行
    - Web task command/upload 执行
    - RemoteExecutionService 对 history 的辅助 API

    后续可继续承接：
    - command_id -> history_entry_id 绑定
    - artifact -> history_entry 反向绑定
    """

    def __init__(self, history_store):
        self.history_store = history_store

    def should_record_command(self, command: str) -> bool:
        """
        判断命令是否应该进入历史。
        先沿用当前既有规则：
        - 空命令不记
        - history* 命令不记
        """
        command_text = (command or '').strip()
        if not command_text:
            return False
        return not command_text.startswith('history')

    def begin_execution(self, conn, command: str, source: str = 'cli', should_record=None) -> str:
        """
        为一次执行创建 history entry。
        """
        if conn is None:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        if should_record is None:
            should_record = self.should_record_command(command_text)

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

    def finalize_execution(self, conn, entry_id: str, ok: bool, cwd_end: str = ''):
        """
        统一结束一次执行历史。
        """
        if conn is None or not entry_id:
            return

        final_cwd = cwd_end or (getattr(conn, 'info', {}) or {}).get('cwd', '')
        self.history_store.update_entry_status_for_connection(
            conn,
            entry_id,
            'success' if ok else 'error',
            cwd_end=final_cwd
        )