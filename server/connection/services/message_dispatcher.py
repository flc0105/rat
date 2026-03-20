class ServerInboundMessageDispatcher:
    """
    Server 侧入站消息调度器。

    职责：
    - 决定消息如何进入后续处理流程
    - 当前服务端收到的消息都由接收线程即时分发
    - 保持与 client 侧 dispatcher + router 的结构一致
    """

    IMMEDIATE_MESSAGE_TYPES = {'rdy', 'result', 'file'}

    def __init__(self, connection):
        self.connection = connection

    def dispatch(self, data: dict):
        """
        调度一条收到的消息。
        """
        message_type = data.get('type')

        if message_type in self.IMMEDIATE_MESSAGE_TYPES:
            return self._dispatch_immediate_message(data)

        return self._dispatch_unknown_message(data)

    def _dispatch_immediate_message(self, data: dict):
        """
        立即处理的消息：
        - rdy
        - result
        - file
        """
        return self.connection.services.message_router.dispatch(data)

    def _dispatch_unknown_message(self, data: dict):
        """
        未知消息默认忽略
        """
        return None