import ntpath
import os
from typing import Generator


class ClientSessionCommandChannel:
    """
    客户端会话命令通道。

    职责：
    - 生成连接内唯一消息 ID
    - 构造命令/文件消息
    - 发送命令
    - 发送文件
    - 等待结果

    说明：
    - 不直接持有 socket，自身通过 connection 调用底层 send / send_file_by_header
    - 运行态队列与等待逻辑委托给 runtime
    """

    def __init__(self, connection):
        self.connection = connection
        self._message_id_counter = 0

    # ------------------ id / payload builders ------------------ #
    def generate_message_id(self) -> int:
        """
        生成连接内唯一的消息 ID
        """
        self._message_id_counter += 1
        return self._message_id_counter

    def build_command_payload(self, command: str, command_type: str = 'command', extra=None) -> dict:
        """
        构造命令消息
        """
        data = {
            'type': command_type,
            'id': self.generate_message_id(),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        return data

    def build_file_payload(self, filename: str, save_dir: str = '') -> dict:
        """
        构造文件消息头
        """
        data = {
            'type': 'file',
            'id': self.generate_message_id(),
            'length': os.stat(filename).st_size,
            'filename': ntpath.basename(filename),
        }
        if save_dir:
            data['save_dir'] = save_dir
        return data

    # ------------------ command / file send ------------------ #
    def send_command(self, command: str, type='command', extra=None, history_entry_id: str = '') -> Generator:
        """
        向客户端发送命令

        :param command: 命令
        :param type: 命令类型
        :param extra: 额外信息
        :param history_entry_id: 执行记录 entry_id
        :return: 结果生成器
        """
        data = self.build_command_payload(command, type, extra)

        if history_entry_id:
            self.connection.bind_history_entry(data.get('id'), history_entry_id)

        self.connection.send(data)
        return self.wait_for_result(data.get('id'), command if type == 'command' else None)

    def send_file(self, filename: str, save_dir: str = '', history_entry_id: str = '') -> Generator:
        """
        向客户端发送文件

        :param filename: 文件名
        :param save_dir: 客户端保存目录
        :param history_entry_id: 执行记录 entry_id
        :return: 结果生成器
        """
        data = self.build_file_payload(filename, save_dir)

        if history_entry_id:
            self.connection.bind_history_entry(data.get('id'), history_entry_id)

        self.connection.send_file_by_header(data, filename)
        return self.wait_for_result(data.get('id'), 'upload ' + filename)

    # ------------------ result wait ------------------ #
    def wait_for_result(self, command_id: int, command: str = ''):
        """
        主线程等待接收结果，并保存执行记录
        """
        yield from self.connection.runtime.wait_for_result(self.connection, command_id, command)