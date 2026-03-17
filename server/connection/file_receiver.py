import json
import ntpath
import os
from datetime import datetime


class ClientFileReceiver:
    """
    ClientConnection 文件接收器。

    职责：
    - 生成接收文件保存路径
    - 接收并保存文件
    - 写入元数据
    - 触发文件保存回调
    """

    def __init__(self, connection):
        self.connection = connection

    def save_file(self, filename, length):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        target_dir = self.connection.file_save_dir or os.getcwd()
        os.makedirs(target_dir, exist_ok=True)

        original_name = ntpath.basename(filename) or os.path.basename(filename)
        file_path = self._build_unique_file_path(target_dir, original_name)

        try:
            from core.utils.files import get_input_stream
            io = get_input_stream(file_path)
            try:
                self.connection.send_signal(1)
                self.connection.recv_io(length, io)

                self._write_file_meta(file_path, original_name, length)
                self._notify_file_saved(original_name, file_path, length)

                return 1, f'File saved to: {file_path}'
            except Exception as e:
                return 0, f'Error receiving file from {self.connection.address}: {e}'
        except Exception as e:
            self.connection.send_signal(0)
            return 0, f'Error opening local file: {e}'

    def _build_unique_file_path(self, directory: str, filename: str) -> str:
        safe_name = ntpath.basename(filename) or 'file.bin'
        base, ext = os.path.splitext(safe_name)
        candidate = os.path.join(directory, safe_name)
        index = 1
        while os.path.exists(candidate):
            candidate = os.path.join(directory, f'{base}_{index}{ext}')
            index += 1
        return candidate

    def _write_file_meta(self, file_path: str, original_name: str, size: int):
        meta_path = file_path + '.meta.json'
        meta = {
            'client_id': self.connection.info.get('id'),
            'hostname': self.connection.info.get('hostname'),
            'addr': self.connection.info.get('addr'),
            'original_name': original_name,
            'saved_name': os.path.basename(file_path),
            'saved_path': file_path,
            'size': size,
            'created_at': datetime.now().isoformat()
        }
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    def _notify_file_saved(self, original_name: str, file_path: str, length: int):
        if callable(self.connection.on_file_saved):
            try:
                self.connection.on_file_saved(original_name, file_path, length)
            except Exception:
                pass