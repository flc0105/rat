import ntpath
import os

from core.utils.files import get_input_stream


class ClientFileReceiver:
    """
    ClientConnection 文件接收器。

    职责：
    - 生成接收文件保存路径
    - 接收并保存文件
    - 写入统一 artifact 元数据
    - 触发文件保存回调
    """

    def __init__(self, connection):
        self.connection = connection

    def save_file(self, command_id, filename, length):
        """
        保存文件
        :param command_id: 命令 ID
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        file_context = self.connection.pop_file_receive_context(command_id) or {}
        on_file_saved = file_context.get('on_file_saved') or self.connection.on_file_saved
        capture_result = file_context.get('capture_result')

        artifact_service = getattr(self.connection, 'artifact_service', None)
        if artifact_service is None:
            self.connection.send_signal(0, command_id)
            return 0, 'Artifact service is not configured'

        original_name = ntpath.basename(filename) or os.path.basename(filename) or 'file.bin'
        hostname = self.connection.info.get('hostname') or 'unknown_host'
        client_id = self.connection.info.get('id') or ''
        addr = self.connection.info.get('addr') or ''

        artifact_type = (file_context.get('artifact_type') or 'downloads').strip() or 'downloads'
        category = (file_context.get('category') or '').strip()
        source_type = (file_context.get('source_type') or 'socket_file').strip()
        related_path = (file_context.get('related_path') or '').strip()
        source_command_id = file_context.get('source_command_id', command_id)
        extra = file_context.get('extra') if isinstance(file_context.get('extra'), dict) else {}

        file_path = ''
        meta_path = ''

        try:
            allocated = artifact_service.allocate_artifact_path(
                artifact_type=artifact_type,
                hostname=hostname,
                original_name=original_name,
                category=category,
            )
            file_path = allocated['file_path']
            meta_path = allocated['meta_path']

            io = get_input_stream(file_path)
        except Exception as e:
            self.connection.send_signal(0, command_id)
            return 0, f'Error opening local file: {e}'

        try:
            status, error = self.connection.recv_file_packet(command_id, length, io)
            if status != 1:
                self._rollback_artifact_files(file_path, meta_path)
                return 0, f'Error receiving file from {self.connection.address}: {error}'

            artifact_info = artifact_service.register_existing_artifact(
                artifact_type=artifact_type,
                category=category,
                hostname=allocated['hostname'],
                original_name=original_name,
                file_path=file_path,
                meta_path=meta_path,
                stored_name=allocated['stored_name'],
                source_type=source_type,
                source_command_id=source_command_id,
                client_id=client_id,
                addr=addr,
                related_path=related_path,
                extra=extra,
            )

            self._notify_file_saved(on_file_saved, artifact_info)
            self._append_file_history(command_id, artifact_info)

            if isinstance(capture_result, dict):
                capture_result['artifact'] = artifact_info

            return 1, f'File saved to: {artifact_info.get("saved_path", file_path)}'
        except Exception as e:
            self._rollback_artifact_files(file_path, meta_path)
            return 0, f'Error receiving file from {self.connection.address}: {e}'

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