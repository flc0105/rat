import ntpath
import os

from core.utils.files import get_input_stream
from server.models.artifact import ArtifactRecord, FileReceiveContext


class ArtifactIngestService:
    """
    Artifact 接收编排服务。

    职责：
    - 读取文件接收上下文
    - 申请 artifact 落盘路径
    - 驱动底层文件接收
    - 注册 artifact
    - 挂接 command history
    - 触发回调 / capture_result
    - 在失败时执行回滚
    """

    def __init__(self, connection):
        self.connection = connection

    def receive_artifact_file(self, command_id, filename, length):
        """
        接收客户端上传的文件并注册为 artifact
        """
        file_context = self.connection.pop_file_receive_context(command_id)
        if not isinstance(file_context, FileReceiveContext):
            file_context = FileReceiveContext.from_dict(None)

        on_file_saved = file_context.on_file_saved or self.connection.on_file_saved
        capture_result = file_context.capture_result

        artifact_service = getattr(self.connection, 'artifact_service', None)
        if artifact_service is None:
            self.connection.send_signal(0, command_id)
            return 0, 'Artifact service is not configured'

        original_name = self._resolve_original_name(filename)
        hostname = self.connection.info.get('hostname') or 'unknown_host'
        client_id = self.connection.info.get('id') or ''
        addr = self.connection.info.get('addr') or ''

        file_path = ''
        meta_path = ''

        try:
            allocated = artifact_service.allocate_artifact_path(
                artifact_type=file_context.artifact_type,
                hostname=hostname,
                original_name=original_name,
                category=file_context.category,
            )
            file_path = allocated['file_path']
            meta_path = allocated['meta_path']

            io = get_input_stream(file_path)
        except Exception as e:
            self.connection.send_signal(0, command_id)
            return 0, f'Error opening local file: {e}'

        try:
            status, error = self.connection.file_receiver.receive_to_io(command_id, length, io)
            if status != 1:
                self._rollback_artifact_files(file_path, meta_path)
                return 0, f'Error receiving file from {self.connection.address}: {error}'

            artifact_info = artifact_service.register_existing_artifact(
                artifact_type=file_context.artifact_type,
                category=file_context.category,
                hostname=allocated['hostname'],
                original_name=original_name,
                file_path=file_path,
                meta_path=meta_path,
                stored_name=allocated['stored_name'],
                source_type=file_context.source_type,
                source_command_id=(
                    file_context.source_command_id
                    if file_context.source_command_id is not None
                    else command_id
                ),
                client_id=client_id,
                addr=addr,
                related_path=file_context.related_path,
                extra=file_context.extra,
            )

            self._notify_file_saved(on_file_saved, artifact_info)
            self._append_file_history(command_id, artifact_info)

            if isinstance(capture_result, dict):
                capture_result['artifact'] = artifact_info

            artifact = ArtifactRecord.from_dict(artifact_info)
            return 1, f'File saved to: {artifact.saved_path or file_path}'
        except Exception as e:
            self._rollback_artifact_files(file_path, meta_path)
            return 0, f'Error receiving file from {self.connection.address}: {e}'

    def _resolve_original_name(self, filename: str) -> str:
        return ntpath.basename(filename) or os.path.basename(filename) or 'file.bin'

    def _append_file_history(self, command_id: int, artifact_info: dict):
        """
        将收到的文件挂到对应执行记录上
        """
        self.connection.append_file_to_history(command_id, artifact_info)

    def _notify_file_saved(self, callback, artifact_info: dict):
        if callable(callback):
            try:
                callback(artifact_info)
            except Exception:
                pass

    def _rollback_artifact_files(self, file_path: str, meta_path: str):
        """
        文件接收 / artifact 注册失败时回滚落盘文件，避免孤儿文件残留。
        """
        for path in (file_path, meta_path):
            try:
                if path and os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass