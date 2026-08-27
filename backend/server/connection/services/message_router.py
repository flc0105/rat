from core.protocol.message_router_base import BaseMessageRouter


class ServerInboundMessageRouter(BaseMessageRouter):
    """
    Server 侧入站消息路由器。
    旧 file / rdy 消息已移除。
    """

    def handle_result_message(self, data: dict) -> None:
        self.connection.update_current_workdir(data.get('cwd'))
        self.connection.services.result_dispatcher.dispatch_result(
            data.get('id'),
            data.get('status'),
            data.get('text'),
            data.get('eof')
        )

    def handle_heartbeat_ack_message(self, data: dict) -> None:
        self.connection.update_current_workdir(data.get('cwd'))
        self.connection.services.heartbeat_service.handle_heartbeat_ack(data)


    def handle_pty_opened_message(self, data: dict) -> None:
        callback = self.connection.context.on_pty_opened
        if callable(callback):
            callback(
                data.get('pty_session_id') or '',
                data.get('shell') or '',
            )

    def handle_pty_output_message(self, data: dict) -> None:
        callback = self.connection.context.on_pty_output
        if callable(callback):
            callback(data.get('pty_session_id') or '', data.get('data') or '')

    def handle_pty_closed_message(self, data: dict) -> None:
        callback = self.connection.context.on_pty_closed
        if callable(callback):
            callback(data.get('pty_session_id') or '', data.get('exit_code'))

    def handle_pty_error_message(self, data: dict) -> None:
        callback = self.connection.context.on_pty_error
        if callable(callback):
            callback(data.get('pty_session_id') or '', data.get('message') or '')

    def handle_screen_opened_message(self, data: dict) -> None:
        callback = self.connection.context.on_screen_opened
        if callable(callback):
            callback(
                data.get('screen_session_id') or '',
                data.get('fps'),
                data.get('quality'),
            )

    def handle_screen_frame_message(self, data: dict) -> None:
        callback = self.connection.context.on_screen_frame
        if callable(callback):
            callback(
                data.get('screen_session_id') or '',
                data.get('data') or '',
                data.get('width') or 0,
                data.get('height') or 0,
                data.get('bytes') or 0,
                data.get('captured_at') or 0,
            )

    def handle_screen_closed_message(self, data: dict) -> None:
        callback = self.connection.context.on_screen_closed
        if callable(callback):
            callback(data.get('screen_session_id') or '')

    def handle_screen_error_message(self, data: dict) -> None:
        callback = self.connection.context.on_screen_error
        if callable(callback):
            callback(data.get('screen_session_id') or '', data.get('message') or '')

    def handle_screen_input_error_message(self, data: dict) -> None:
        callback = self.connection.context.on_screen_input_error
        if callable(callback):
            callback(data.get('screen_session_id') or '', data.get('message') or '')










