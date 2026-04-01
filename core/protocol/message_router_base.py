class BaseMessageRouter:
    """
    消息分发基类。
    """

    def __init__(self, connection):
        self.connection = connection

    def dispatch(self, data: dict):
        message_type = data.get('type')

        if message_type == 'result':
            return self.handle_result_message(data)

        if message_type == 'command':
            return self.handle_command_message(data)

        if message_type == 'script':
            return self.handle_script_message(data)

        if message_type == 'acmd':
            return self.handle_acmd_message(data)

        if message_type == 'cancel':
            return self.handle_cancel_message(data)

        if message_type == 'heartbeat':
            return self.handle_heartbeat_message(data)

        if message_type == 'heartbeat_ack':
            return self.handle_heartbeat_ack_message(data)

        return self.handle_unknown_message(data)

    def handle_result_message(self, data: dict):
        return None

    def handle_command_message(self, data: dict):
        return None

    def handle_script_message(self, data: dict):
        return None

    def handle_acmd_message(self, data: dict):
        return None

    def handle_cancel_message(self, data: dict):
        return None

    def handle_heartbeat_message(self, data: dict):
        return None

    def handle_heartbeat_ack_message(self, data: dict):
        return None

    def handle_unknown_message(self, data: dict):
        return None



