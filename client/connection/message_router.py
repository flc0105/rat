import os
import time

from core.protocol.message_router_base import BaseMessageRouter


class ClientInboundMessageRouter(BaseMessageRouter):
    """
    Client 侧入站消息路由器。
    """

    def handle_command_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.command_executor.execute_command(command_id, data.get('text'))
        if result:
            return command_id, *result
        return None

    def handle_script_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.common_commands.pyexec(data['text'], kwargs=data.get('extra'))
        return command_id, *result

    def handle_acmd_message(self, data: dict):
        command_id = data.get('id')
        result = self.connection.command_executor.execute_argument_command(
            command_id,
            data.get('extra') or {}
        )
        if result:
            return command_id, *result
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
