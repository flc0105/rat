class BaseMessageRouter:
    """
    消息分发基类。

    职责：
    - 提供统一的 dispatch 骨架
    - 按消息 type 调用对应处理器
    - 具体业务处理由子类实现
    """

    def __init__(self, connection):
        self.connection = connection

    def dispatch(self, data: dict):
        """
        根据消息类型分发处理
        """
        message_type = data.get('type')

        if message_type == 'rdy':
            return self.handle_ready_message(data)

        if message_type == 'result':
            return self.handle_result_message(data)

        if message_type == 'file':
            return self.handle_file_message(data)

        if message_type == 'command':
            return self.handle_command_message(data)

        if message_type == 'script':
            return self.handle_script_message(data)

        return self.handle_unknown_message(data)

    def handle_ready_message(self, data: dict):
        return None

    def handle_result_message(self, data: dict):
        return None

    def handle_file_message(self, data: dict):
        return None

    def handle_command_message(self, data: dict):
        return None

    def handle_script_message(self, data: dict):
        return None

    def handle_unknown_message(self, data: dict):
        return None