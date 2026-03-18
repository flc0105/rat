class ServerMessageRouter:
    """
    ServerConnection 收到消息后的分发器。

    职责：
    - 按消息 type 分发到对应处理逻辑
    - 不直接关心 socket 运行态之外的业务细节
    """

    def __init__(self, connection):
        self.connection = connection

    def dispatch(self, data: dict):
        """
        根据消息类型分发处理
        """
        command_id = data.get('id')
        command_type = data.get('type')

        if command_type == 'command':
            return self._handle_command_message(command_id, data)

        if command_type == 'script':
            return self._handle_script_message(command_id, data)

        if command_type == 'file':
            return self._handle_file_message(command_id, data)

        if command_type == 'rdy':
            return self._handle_ready_message(data)

        return None

    def _handle_command_message(self, command_id: int, data: dict):
        """
        处理普通命令消息
        """
        result = self.connection.command_executor.execute_command(command_id, data.get('text'))
        if result:
            return command_id, *result
        return None

    def _handle_script_message(self, command_id: int, data: dict):
        """
        处理 Python 脚本消息
        """
        result = self.connection.common_commands.pyexec(data['text'], kwargs=data.get('extra'))
        return command_id, *result

    def _handle_file_message(self, command_id: int, data: dict):
        """
        处理文件消息
        """
        result = self.connection.file_receiver.save_file(
            command_id,
            data.get('filename'),
            data.get('length'),
            data.get('save_dir', '')
        )
        if result:
            return command_id, *result
        return None

    def _handle_ready_message(self, data: dict):
        """
        处理就绪信号
        """
        self.connection.ready_queue.put(data.get('id'), data.get('status'))
        return None