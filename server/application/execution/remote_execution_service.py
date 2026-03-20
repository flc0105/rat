import json


class RemoteExecutionService:
    """
    统一远程执行服务。

    职责：
    - 根据 client_id / session 获取目标会话
    - 统一执行远程文本命令 / 结构化命令
    - 统一上传文件
    - 统一抓取 artifact
    - 提供 history entry 创建 / 结束辅助能力
    """

    def __init__(self, server):
        self.server = server

    # ------------------ session helpers ------------------ #
    def get_connection(self, target):
        """
        target 支持：
        - client_id: str
        - ClientSession 实例
        """
        if hasattr(target, 'send_command') and hasattr(target, 'send_file'):
            return target
        return self.server.get_target_connection_by_client_id(str(target))

    # ------------------ history helpers ------------------ #
    def create_history_entry(self, target, command: str, source: str = 'cli', should_record: bool = True) -> str:
        """
        创建执行记录并返回 entry_id
        """
        if not should_record:
            return ''

        session = self.get_connection(target)
        command_text = (command or '').strip()
        if not command_text:
            return ''

        return self.server.command_history.create_entry_for_connection(
            session,
            command_text,
            source=source
        )

    def finalize_history_entry(self, target, entry_id: str, ok: bool, cwd_end: str = ''):
        """
        结束执行记录
        """
        if not entry_id:
            return

        session = self.get_connection(target)
        self.server.command_history.update_entry_status_for_connection(
            session,
            entry_id,
            'success' if ok else 'error',
            cwd_end=cwd_end or (getattr(session, 'info', {}) or {}).get('cwd', '')
        )

    def append_history_output(self, target, entry_id: str, status: int, text: str, eof: int = 0):
        """
        追加执行输出到 history
        """
        if not entry_id:
            return

        session = self.get_connection(target)
        self.server.command_history.append_output_for_connection(
            session,
            entry_id,
            status,
            text,
            eof
        )

    # ------------------ result helpers ------------------ #
    def collect_result(self, result_iter):
        """
        收集生成器结果为单个文本
        """
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    # ------------------ stream execution ------------------ #
    def stream_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ):
        """
        以结果流方式执行远程命令
        """
        session = self.get_connection(target)
        return session.send_command(
            command,
            type=command_type,
            extra=extra,
            history_entry_id=history_entry_id
        )

    def stream_structured_command(
        self,
        target,
        command: str,
        *,
        command_type: str,
        extra,
        history_entry_id: str = '',
    ):
        """
        结构化命令结果流执行
        """
        return self.stream_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
        )

    def stream_upload(
        self,
        target,
        local_path: str,
        *,
        remote_path: str = '',
        history_entry_id: str = '',
    ):
        """
        以上传结果流方式执行文件上传
        """
        session = self.get_connection(target)
        return session.send_file(
            local_path,
            save_dir=remote_path,
            history_entry_id=history_entry_id
        )

    # ------------------ text / json execution ------------------ #
    def run_text_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ) -> str:
        """
        执行远程命令并返回最终文本
        """
        status, text = self.collect_result(
            self.stream_command(
                target,
                command,
                command_type=command_type,
                extra=extra,
                history_entry_id=history_entry_id,
            )
        )

        if status != 1:
            raise RuntimeError(text or 'Remote command failed')

        return text

    def run_json_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ) -> dict:
        """
        执行远程命令并解析 JSON 对象
        """
        text = self.run_text_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
        )

        try:
            payload = json.loads(text or '{}')
        except Exception as e:
            raise RuntimeError(f'Invalid remote JSON payload: {e}')

        if not isinstance(payload, dict):
            raise RuntimeError('Invalid remote JSON payload: expected object')

        return payload

    # ------------------ artifact execution ------------------ #
    def fetch_artifact(
        self,
        target,
        command: str,
        *,
        artifact_type: str,
        source_type: str,
        related_path: str = '',
        category: str = '',
        extra: dict | None = None,
        history_entry_id: str = '',
    ) -> dict:
        """
        执行远程命令并接收 artifact
        """
        session = self.get_connection(target)
        command_id = session.command_channel.generate_message_id()
        capture_result = {}

        if history_entry_id:
            session.runtime.bind_history_entry(command_id, history_entry_id)

        session.runtime.set_file_receive_context(
            command_id,
            artifact_type=artifact_type,
            category=category,
            source_type=source_type,
            related_path=related_path,
            source_command_id=command_id,
            capture_result=capture_result,
            extra=extra or {},
        )

        session.send({
            'type': 'command',
            'id': command_id,
            'text': command,
        })

        status, text = self.collect_result(
            session.command_channel.wait_for_result(command_id, command)
        )
        if status != 1:
            raise RuntimeError(text or 'Remote file fetch failed')

        artifact = capture_result.get('artifact') or {}
        if not isinstance(artifact, dict) or not artifact.get('artifact_id'):
            raise RuntimeError('Remote file download completed, but artifact was not found')

        return {
            'message': text,
            'artifact': artifact,
        }