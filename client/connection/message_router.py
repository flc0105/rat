from core.protocol.message_router_base import BaseMessageRouter


class ClientInboundMessageRouter(BaseMessageRouter):
    """
    Client 侧入站消息路由器。

    职责：
    - 按消息 type 分发到对应处理逻辑
    - 不直接关心 socket 运行态之外的业务细节
    """

    def handle_command_message(self, data: dict):
        """
        处理普通命令消息
        """
        command_id = data.get('id')
        result = self.connection.command_executor.execute_command(command_id, data.get('text'))
        if result:
            return command_id, *result
        return None

    def handle_script_message(self, data: dict):
        """
        处理 Python 脚本消息
        """
        command_id = data.get('id')
        result = self.connection.command_executor.execute_script_command(
            command_id,
            data.get('text', ''),
            kwargs=data.get('extra')
        )
        return command_id, *result

    def handle_acmd_message(self, data: dict):
        """
        处理 acmd 结构化实验命令消息
        """
        command_id = data.get('id')
        result = self.connection.command_executor.execute_argument_command(
            command_id,
            data.get('extra') or {}
        )
        if result:
            return command_id, *result
        return None

    def handle_file_message(self, data: dict):
        """
        处理文件消息
        """
        command_id = data.get('id')
        result = self.connection.file_receiver.save_file(
            command_id,
            data.get('filename'),
            data.get('length'),
            data.get('save_dir', '')
        )
        if result:
            return command_id, *result
        return None

    def handle_ready_message(self, data: dict):
        """
        处理就绪信号
        """
        self.connection.ready_queue.put(data.get('id'), data.get('status'))
        return None