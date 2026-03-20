class ClientSessionCommandChannel:
    """
    客户端会话命令通道。

    职责：
    - 生成消息 id
    - 下发远程命令
    - 等待对应结果返回
    """

    def __init__(self, session):
        self.session = session
        self._message_id_counter = 0

    def generate_message_id(self) -> int:
        self._message_id_counter += 1
        return self._message_id_counter

    def build_command_payload(self, command: str, command_type: str = 'command', extra=None) -> dict:
        data = {
            'type': command_type,
            'id': self.generate_message_id(),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        return data

    def send_command(self, command: str, type='command', extra=None, history_entry_id: str = ''):
        data = self.build_command_payload(command, type, extra)

        if history_entry_id:
            self.session.runtime.bind_history_entry(data.get('id'), history_entry_id)

        self.session.send(data)
        return self.wait_for_result(data.get('id'), command if type == 'command' else None)

    def wait_for_result(self, command_id: int, command: str = ''):
        yield from self.session.runtime.wait_for_result(self.session, command_id, command)
