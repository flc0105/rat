from core.protocol.message_router_base import BaseMessageRouter


class ServerInboundMessageRouter(BaseMessageRouter):
    """
    Server 侧入站消息路由器。
    旧 file / rdy 消息已移除。
    """

    def handle_result_message(self, data: dict) -> None:
        self.connection.info['cwd'] = data.get('cwd')
        self.connection.services.result_dispatcher.dispatch_result(
            data.get('id'),
            data.get('status'),
            data.get('text'),
            data.get('eof')
        )

    def handle_heartbeat_ack_message(self, data: dict) -> None:
        self.connection.info['cwd'] = data.get('cwd') or self.connection.info.get('cwd', '')
        self.connection.services.heartbeat_service.handle_heartbeat_ack(data)






