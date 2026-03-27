import base64
import json
import os


class RemoteExecutionService:
    """
    统一远程执行服务。

    说明：
    - 普通 stream_command / run_text_command / run_json_command：
      不主动占用 foreground task 槽
      适用于已经在上层完成占槽的场景（例如 WebTaskRunner）

    - stream_foreground_command / run_foreground_text_command / run_foreground_json_command：
      在当前方法内部统一占用 foreground task 槽
      适用于前台同步型请求（CLI / remote file / background job 等）
    """

    HTTP_RECEIVE_COMMAND_NAME = 'receive_http_upload'

    def __init__(self, server):
        self.server = server
        self.history_orchestrator = getattr(server, 'command_history_orchestrator', None)

    def get_connection(self, target):
        if hasattr(target, 'send_command'):
            return target
        return self.server.get_target_connection_by_client_id(str(target))

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _build_http_receive_command(self, payload: dict) -> str:
        return f'{self.HTTP_RECEIVE_COMMAND_NAME} {self._encode_payload_arg(payload)}'

    def create_history_entry(self, target, command: str, source: str = 'cli', should_record: bool = True) -> str:
        session = self.get_connection(target)

        if self.history_orchestrator is not None:
            return self.history_orchestrator.begin_execution(
                session,
                command,
                source=source,
                should_record=should_record
            )

        if not should_record:
            return ''

        command_text = (command or '').strip()
        if not command_text:
            return ''

        return self.server.command_history.create_entry_for_connection(
            session,
            command_text,
            source=source
        )

    def finalize_history_entry(self, target, entry_id: str, ok: bool, cwd_end: str = ''):
        if not entry_id:
            return

        session = self.get_connection(target)

        if self.history_orchestrator is not None:
            self.history_orchestrator.finalize_execution(
                session,
                entry_id,
                ok,
                cwd_end=cwd_end
            )
            return

        self.server.command_history.update_entry_status_for_connection(
            session,
            entry_id,
            'success' if ok else 'error',
            cwd_end=cwd_end or (getattr(session, 'info', {}) or {}).get('cwd', '')
        )

    def append_history_output(self, target, entry_id: str, status: int, text: str, eof: int = 0):
        if not entry_id:
            return

        session = self.get_connection(target)

        if self.history_orchestrator is not None:
            self.history_orchestrator.append_output(
                session,
                entry_id,
                status,
                text,
                eof
            )
            return

        self.server.command_history.append_output_for_connection(
            session,
            entry_id,
            status,
            text,
            eof
        )
    def collect_result(self, result_iter):
        final_status = 1
        parts = []

        for status, text in result_iter:
            final_status = status
            if text is not None:
                parts.append(str(text))

        return final_status, '\n'.join(part for part in parts if part).strip()

    # ------------------ raw stream api ------------------ #
    def stream_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ):
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
        return self.stream_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
        )

    # ------------------ foreground guard api ------------------ #
    def stream_foreground_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
        task_type: str = 'command',
        source: str = 'foreground',
        task_id: str = '',
    ):
        """
        统一前台执行入口：
        凡是前台同步等待 session.send_command() 结果流的请求，都必须走这里。
        """
        session = self.get_connection(target)

        acquired_task = session.acquire_foreground_task(
            task_type=task_type,
            command=command,
            source=source,
            task_id=task_id,
        )

        effective_task_id = acquired_task.get('task_id', '') if isinstance(acquired_task, dict) else ''

        try:
            result_iter = session.send_command(
                command,
                type=command_type,
                extra=extra,
                history_entry_id=history_entry_id
            )
            for item in result_iter:
                yield item
        finally:
            session.release_foreground_task(
                task_id=effective_task_id or task_id,
                command=command
            )

    def run_text_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ) -> str:
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

    def run_foreground_text_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
        task_type: str = 'command',
        source: str = 'foreground',
        task_id: str = '',
    ) -> str:
        status, text = self.collect_result(
            self.stream_foreground_command(
                target,
                command,
                command_type=command_type,
                extra=extra,
                history_entry_id=history_entry_id,
                task_type=task_type,
                source=source,
                task_id=task_id,
            )
        )

        if status != 1:
            raise RuntimeError(text or 'Remote command failed')

        return text

    def run_foreground_json_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
        task_type: str = 'command',
        source: str = 'foreground',
        task_id: str = '',
    ) -> dict:
        text = self.run_foreground_text_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
            task_type=task_type,
            source=source,
            task_id=task_id,
        )

        try:
            payload = json.loads(text or '{}')
        except Exception as e:
            raise RuntimeError(f'Invalid remote JSON payload: {e}')

        if not isinstance(payload, dict):
            raise RuntimeError('Invalid remote JSON payload: expected object')

        return payload

    # ------------------ upload ------------------ #
    def stream_upload(
        self,
        target,
        local_path: str,
        *,
        remote_path: str = '',
        history_entry_id: str = '',
    ):
        session = self.get_connection(target)
        artifact_service = self.server.web_service.artifact_service

        staged_path = ''
        try:
            staged_path, safe_name = artifact_service.stage_local_file(
                local_path,
                display_name=os.path.basename(local_path)
            )
            relative_url = artifact_service.build_upload_temp_download_relative_url(staged_path)

            command = self._build_http_receive_command({
                'relative_url': relative_url,
                'filename': safe_name,
                'save_dir': remote_path,
            })

            result_iter = session.send_command(
                command,
                type='command',
                extra=None,
                history_entry_id=history_entry_id
            )

            for item in result_iter:
                yield item
        finally:
            try:
                artifact_service.cleanup_upload_temp_file(staged_path)
            except Exception:
                pass