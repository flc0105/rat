from core.protocol.message_types import (
    MSG_TYPE_HEARTBEAT_ACK,
    MSG_TYPE_RESULT,
    MSG_TYPE_PTY_OPENED,
    MSG_TYPE_PTY_OUTPUT,
    MSG_TYPE_PTY_CLOSED,
    MSG_TYPE_PTY_ERROR,
    MSG_TYPE_SCREEN_OPENED,
    MSG_TYPE_SCREEN_FRAME,
    MSG_TYPE_SCREEN_CLOSED,
    MSG_TYPE_SCREEN_ERROR,
    MSG_TYPE_SCREEN_INPUT_ERROR,
    MSG_TYPE_CLIPBOARD_RESULT,
    MSG_TYPE_MONITOR_OPENED,
    MSG_TYPE_MONITOR_SNAPSHOT,
    MSG_TYPE_MONITOR_ERROR,
    MSG_TYPE_MONITOR_CLOSED,
    MSG_TYPE_TRANSFER_UPDATE,
)


class ServerInboundMessageDispatcher:
    """
    Server 侧入站消息调度器。

    当前仅对需要立即消费的消息做分发：
    - result
    - heartbeat_ack
    """

    IMMEDIATE_MESSAGE_TYPES = {
        MSG_TYPE_RESULT,
        MSG_TYPE_HEARTBEAT_ACK,
        MSG_TYPE_PTY_OPENED,
        MSG_TYPE_PTY_OUTPUT,
        MSG_TYPE_PTY_CLOSED,
        MSG_TYPE_PTY_ERROR,
        MSG_TYPE_SCREEN_OPENED,
        MSG_TYPE_SCREEN_FRAME,
        MSG_TYPE_SCREEN_CLOSED,
        MSG_TYPE_SCREEN_ERROR,
        MSG_TYPE_SCREEN_INPUT_ERROR,
        MSG_TYPE_CLIPBOARD_RESULT,
        MSG_TYPE_MONITOR_OPENED,
        MSG_TYPE_MONITOR_SNAPSHOT,
        MSG_TYPE_MONITOR_ERROR,
        MSG_TYPE_MONITOR_CLOSED,
        MSG_TYPE_TRANSFER_UPDATE,
    }

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