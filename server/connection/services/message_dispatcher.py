class ServerInboundMessageDispatcher:
    """
    Server 侧入站消息调度器。

    当前仅对需要立即消费的消息做分发：
    - result
    - heartbeat_ack
    """

    IMMEDIATE_MESSAGE_TYPES = {'result', 'heartbeat_ack'}

    def __init__(self, session):
        self.session = session

    def dispatch(self, data: dict):
        message_type = data.get('type')

        if message_type in self.IMMEDIATE_MESSAGE_TYPES:
            return self._dispatch_immediate_message(data)

        return self._dispatch_unknown_message(data)

    def _dispatch_immediate_message(self, data: dict):
        return self.session.services.message_router.dispatch(data)

    def _dispatch_unknown_message(self, data: dict):
        return None
