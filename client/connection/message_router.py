import os
import time

from core.protocol.message_router_base import BaseMessageRouter


class ClientInboundMessageRouter(BaseMessageRouter):
    """
    Client 侧入站消息路由器。
    """

    def handle_command_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.command_executor.execute_command(
            command_id,
            data.get('text'),
            options=data.get('extra') if isinstance(data.get('extra'), dict) else None,
        )
        if result:
            return command_id, *result
        return None

    def handle_script_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.command_executor.execute_script_command(
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
        result = self.connection.command_executor.execute_argument_command(
            command_id,
            data.get('extra') or {},
            options=data.get('extra') if isinstance(data.get('extra'), dict) else None,
        )
        if result:
            return command_id, *result
        return None

    def handle_cancel_message(self, data: dict):
        target_command_id = data.get('target_id')
        cancel_result = self.connection.command_executor.cancel_command(target_command_id)
        accepted = bool(cancel_result.get('accepted'))
        message = str(cancel_result.get('message') or '').strip()

        if not accepted and target_command_id:
            self.connection.send_result(target_command_id, 0, message or 'Command does not support cancellation', 0)

        self.connection.send({
            'type': 'cancel_ack',
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
            'type': 'heartbeat_ack',
            'id': data.get('id'),
            'server_ts': data.get('ts'),
            'client_ts': time.time(),
            'cwd': os.getcwd(),
        })
        return None

    def handle_heartbeat_ack_message(self, data: dict):
        return None






