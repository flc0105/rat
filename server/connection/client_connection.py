from core.protocol.base_connection import BaseSessionConnection
from server.connection.channel.session_command_channel import ClientSessionCommandChannel
from server.connection.context.session_context import ClientSessionContext
from server.connection.runtime.session_runtime import ClientSessionRuntime
from server.connection.services.session_services import ClientSessionServices


class ClientConnection(BaseSessionConnection):
    """
    封装每个客户端连接的对象
    """

    FILE_TRANSFER_REJECTED_MESSAGE = 'Client rejected file transfer'

    def __init__(self, sock, address=None, info=None, file_save_dir=None, on_file_saved=None):
        super().__init__()
        self.socket = sock
        self.address = address
        self.info = info or {}

        self.runtime = ClientSessionRuntime()
        self.context = ClientSessionContext(
            file_save_dir=file_save_dir,
            on_file_saved=on_file_saved
        )
        self.services = ClientSessionServices(self)
        self.command_channel = ClientSessionCommandChannel(self)

    # ------------------ history binding ------------------ #
    def bind_history_entry(self, command_id: int, entry_id: str):
        """
        绑定 command_id -> history entry_id
        """
        self.runtime.bind_history_entry(command_id, entry_id)

    def get_history_entry_id(self, command_id: int) -> str:
        """
        获取指定 command_id 绑定的 history entry_id
        """
        return self.runtime.get_history_entry_id(command_id)

    def clear_history_entry(self, command_id: int):
        """
        清理指定 command_id 的历史绑定
        """
        self.runtime.clear_history_entry(command_id)

    def append_file_to_history(self, command_id: int, file_info: dict):
        """
        将接收到的文件挂到对应执行记录上
        """
        if self.context.command_history is None:
            return

        entry_id = self.runtime.get_history_entry_id(command_id)
        if not entry_id:
            return

        try:
            self.context.command_history.append_file_for_connection(self, entry_id, file_info)
        except Exception:
            pass

    # ------------------ send helpers ------------------ #
    def send_command(self, command: str, type='command', extra=None, history_entry_id: str = ''):
        """
        向客户端发送命令
        """
        return self.command_channel.send_command(
            command,
            type=type,
            extra=extra,
            history_entry_id=history_entry_id
        )

    def send_file(self, filename: str, save_dir: str = '', history_entry_id: str = ''):
        """
        向客户端发送文件
        """
        return self.command_channel.send_file(
            filename,
            save_dir=save_dir,
            history_entry_id=history_entry_id
        )

    # ------------------ receive helpers ------------------ #
    def handle_received_message(self, data: dict):
        """
        处理接收线程收到的消息
        """
        return self.services.message_dispatcher.dispatch(data)

    def set_file_receive_context(self, command_id: int, **context):
        """
        为指定命令设置文件接收上下文
        """
        self.runtime.set_file_receive_context(command_id, **context)

    def pop_file_receive_context(self, command_id: int):
        """
        取出并删除指定命令的文件接收上下文
        """
        return self.runtime.pop_file_receive_context(command_id)

    def save_file(self, command_id, filename, length):
        """
        保存文件
        :param filename: 文件名
        :param length: 文件长度
        :return: 文件保存结果元组 (status, message)
        """
        return self.services.file_receiver.save_file(command_id, filename, length)

    # ------------------ foreground lock ------------------ #
    def acquire_foreground_task(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        """
        尝试占用当前连接的前台执行槽。
        """
        return self.runtime.acquire_foreground_task(
            task_type=task_type,
            command=command,
            source=source,
            task_id=task_id
        )

    def release_foreground_task(self, task_id: str = '', command: str = '') -> None:
        """
        释放当前连接的前台执行槽。
        """
        self.runtime.release_foreground_task(task_id=task_id, command=command)

    def get_foreground_task(self):
        """
        获取当前连接的前台占用信息快照
        """
        return self.runtime.get_foreground_task()