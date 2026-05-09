import os
import time

from core.protocol.message_router_base import BaseMessageRouter
from core.protocol.message_types import MSG_TYPE_CANCEL_ACK, MSG_TYPE_HEARTBEAT_ACK


class ClientInboundMessageRouter(BaseMessageRouter):
    """
    Client 侧入站消息路由器。
    """

    def handle_command_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.runtime.command_executor.execute_command(
            command_id,
            data.get('text'),
            options=data.get('extra') if isinstance(data.get('extra'), dict) else None,
        )
        if result:
            return command_id, *result
        return None

    def handle_script_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.runtime.command_executor.execute_script_command(
            command_id,
            data.get('text') or '',
            kwargs=data.get('extra'),
            options=data.get('extra') if isinstance(data.get('extra'), dict) else None,
        )
        if result:
            return command_id, *result
        return None

    def handle_acmd_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.runtime.command_executor.execute_argument_command(
            command_id,
            data.get('extra') or {},
            options=data.get('extra') if isinstance(data.get('extra'), dict) else None,
        )
        if result:
            return command_id, *result
        return None

    def handle_cancel_message(self, data: dict):
        target_command_id = data.get('target_id')
        cancel_result = self.connection.runtime.command_executor.cancel_command(target_command_id)
        accepted = bool(cancel_result.get('accepted'))
        message = str(cancel_result.get('message') or '').strip()

        if not accepted and target_command_id:
            self.connection.send_result(target_command_id, 0, message or 'Command does not support cancellation', 0)

        self.connection.send({
            'type': MSG_TYPE_CANCEL_ACK,
            'id': data.get('id'),
            'target_id': target_command_id,
            'accepted': accepted,
            'message': message,
            'cwd': os.getcwd(),
            'client_ts': time.time(),
        })
        return None

    def handle_heartbeat_message(self, data: dict):
        self.connection.send({
            'type': MSG_TYPE_HEARTBEAT_ACK,
            'id': data.get('id'),
            'server_ts': data.get('ts'),
            'client_ts': time.time(),
            'cwd': os.getcwd(),
        })
        return None


    def handle_pty_open_message(self, data: dict):
        self.connection.runtime.pty_manager.open_session(
            data.get('pty_session_id') or '',
            shell=data.get('shell') or '',
            cwd=data.get('cwd') or '',
            cols=data.get('cols') or 120,
            rows=data.get('rows') or 32,
        )
        return None

    def handle_pty_input_message(self, data: dict):
        self.connection.runtime.pty_manager.write_input(
            data.get('pty_session_id') or '',
            data.get('data') or '',
        )
        return None

    def handle_pty_resize_message(self, data: dict):
        self.connection.runtime.pty_manager.resize_session(
            data.get('pty_session_id') or '',
            data.get('cols') or 120,
            data.get('rows') or 32,
        )
        return None

    def handle_pty_close_message(self, data: dict):
        self.connection.runtime.pty_manager.close_session(data.get('pty_session_id') or '')
        return None

    def handle_heartbeat_ack_message(self, data: dict):
        return None