from core.protocol.connection_mixins import ReadyFileTransferMixin, ReceiverDispatchMixin
from core.protocol.message_queue import ReadySignalQueue
from core.protocol.ratsocket import RATSocket
from core.utils.files import get_output_stream


class BaseSessionConnection(ReceiverDispatchMixin, ReadyFileTransferMixin, RATSocket):
    """
    会话连接基类。

    职责：
    - 提供接收线程统一入口 recv_message
    - 提供带 ready 的文件发送骨架
    - 提供 ready_queue 初始化与清理
    """

    def __init__(self):
        super().__init__()
        self.ready_queue = ReadySignalQueue()

    def reset_transfer_runtime(self):
        """
        清理与文件传输相关的运行态
        """
        try:
            self.ready_queue.clear()
        except Exception:
            pass

    def send_file_by_header(self, header: dict, filename: str):
        """
        根据已构造好的文件头发送文件
        """
        io = get_output_stream(filename)
        self._send_file_with_ready(header, io)