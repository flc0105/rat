import base64
import json

from server.application.execution.command_stream_service import CommandStreamService
from server.application.execution.foreground_execution_service import ForegroundExecutionService
from server.application.execution.upload_execution_service import UploadExecutionService


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

    当前重构说明：
    - raw command stream / collect_result 下沉到 CommandStreamService
    - foreground 占槽执行下沉到 ForegroundExecutionService
    - upload staging / receive_http_upload 下沉到 UploadExecutionService
    - RemoteExecutionService 保留为兼容 facade
    - history 相关统一优先委托给 command_history_orchestrator
    """

    HTTP_RECEIVE_COMMAND_NAME = 'receive_http_upload'

    def __init__(self, server):
        self.server = server
        self.history_orchestrator = getattr(server, 'command_history_orchestrator', None)

        self.command_stream_service = CommandStreamService(server)
        self.foreground_execution_service = ForegroundExecutionService(
            self.command_stream_service
        )
        self.upload_execution_service = UploadExecutionService(
            server,
            self.command_stream_service,
            artifact_service=getattr(getattr(server, 'web_service', None), 'artifact_service', None),
        )

    def get_connection(self, target):
        return self.command_stream_service.get_connection(target)

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _build_http_receive_command(self, payload: dict) -> str:
        return f'{self.HTTP_RECEIVE_COMMAND_NAME} {self._encode_payload_arg(payload)}'

    # ------------------ history helper api ------------------ #
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

        self.server.command_history.finish_entry(
            entry_id,
            ok=ok,
            cwd_end=cwd_end or session.info.get('cwd', '')
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

        self.server.command_history.append_output(
            entry_id,
            status,
            text,
            eof=eof
        )

    # ------------------ raw command stream api ------------------ #
    def stream_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ):
        return self.command_stream_service.stream_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
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
        return self.command_stream_service.run_text_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
        )

    def run_json_command(
        self,
        target,
        command: str,
        *,
        command_type: str = 'command',
        extra=None,
        history_entry_id: str = '',
    ) -> dict:
        return self.command_stream_service.run_json_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
        )

    def collect_result(self, result_iter):
        return self.command_stream_service.collect_result(result_iter)

    # ------------------ foreground execution api ------------------ #
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
        return self.foreground_execution_service.stream_foreground_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
            task_type=task_type,
            source=source,
            task_id=task_id,
        )

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
        return self.foreground_execution_service.run_foreground_text_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
            task_type=task_type,
            source=source,
            task_id=task_id,
        )

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
        return self.foreground_execution_service.run_foreground_json_command(
            target,
            command,
            command_type=command_type,
            extra=extra,
            history_entry_id=history_entry_id,
            task_type=task_type,
            source=source,
            task_id=task_id,
        )

    # ------------------ upload execution api ------------------ #
    def stream_upload(
        self,
        target,
        local_path: str,
        *,
        remote_path: str = '',
        history_entry_id: str = '',
    ):
        return self.upload_execution_service.stream_upload(
            target,
            local_path,
            remote_path=remote_path,
            history_entry_id=history_entry_id,
            build_http_receive_command=self._build_http_receive_command,
        )