import os

from core.utils.files import get_input_stream
from core.utils.logger import logger


class ServerFileReceiver:
    """
    ServerConnection 文件接收器。

    职责：
    - 接收服务端发送的文件
    - 保存到本地路径
    - 返回统一结果
    """

    def __init__(self, connection):
        self.connection = connection

    def save_file(self, command_id, filename, length, save_dir=''):
        if save_dir:
            target_dir = os.path.abspath(save_dir)
            os.makedirs(target_dir, exist_ok=True)
            file = os.path.join(target_dir, os.path.basename(filename))
        else:
            file = os.path.abspath(filename)
        try:
            io = get_input_stream(file)
        except Exception as e:
            self.connection.send_signal(0, command_id)
            return 0, str(e)

        try:
            self.connection.send_signal(1, command_id)
            self.connection.recv_io(length, io)
            return 1, f'File uploaded to: {os.path.abspath(file)}'
        except Exception as e:
            logger.error(f'Error receiving file from server: {e}', exc_info=True)
            return 0, f'Error receiving file from server: {e}'