from core.protocol.message_router_base import BaseMessageRouter


class ClientMessageRouter(BaseMessageRouter):
    """
    ClientConnection 收到消息后的分发器。

    职责：
    - 按消息 type 分发到对应处理逻辑
    - 不关心结果最终进入哪个队列
    - 只关心“收到什么消息，就调用什么处理器”
    """

    def handle_ready_message(self, data: dict) -> None:
        """
        处理文件传输就绪信号
        """
        self.connection.ready_queue.put(data.get('id'), data.get('status'))

    def handle_result_message(self, data: dict) -> None:
        """
        处理命令执行结果消息
        """
        self.connection.info['cwd'] = data.get('cwd')
        self.connection.result_dispatcher.dispatch_result(
            data.get('id'),
            data.get('status'),
            data.get('text'),
            data.get('eof')
        )

    def handle_file_message(self, data: dict) -> None:
        """
        处理客户端上传的文件消息
        """
        self.connection.info['cwd'] = data.get('cwd')
        status, text = self.connection.save_file(
            data.get('id'),
            data.get('filename'),
            data.get('length')
        )
        self.connection.result_dispatcher.dispatch_result(
            data.get('id'),
            status,
            text,
            1
        )