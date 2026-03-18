class ClientInboundMessageDispatcher:
    """
    Client 侧入站消息调度器。

    职责：
    - 决定消息应立即处理还是交给主线程
    - 复用 message_router 的具体处理逻辑
    - 返回接收线程是否需要立即 send_result
    """

    IMMEDIATE_MESSAGE_TYPES = {'rdy', 'file'}
    DEFERRED_MESSAGE_TYPES = {'command', 'script'}

    def __init__(self, connection):
        self.connection = connection

    def dispatch(self, data: dict):
        """
        调度一条收到的消息。

        返回值：
        - None: 该消息已处理完成，调用方无需额外动作
        - tuple: 需要由接收线程立即 send_result(*result)
        """
        message_type = data.get('type')

        if message_type in self.IMMEDIATE_MESSAGE_TYPES:
            return self._dispatch_immediate_message(data)

        if message_type in self.DEFERRED_MESSAGE_TYPES:
            return self._dispatch_deferred_message(data)

        return self._dispatch_unknown_message(data)

    def _dispatch_immediate_message(self, data: dict):
        """
        立即处理的消息：
        - rdy
        - file
        """
        return self.connection.message_router.dispatch(data)

    def _dispatch_deferred_message(self, data: dict):
        """
        交给主线程处理的消息：
        - command
        - script
        """
        self.connection.enqueue_pending_message(data)
        return None

    def _dispatch_unknown_message(self, data: dict):
        """
        未知消息默认忽略
        """
        return None