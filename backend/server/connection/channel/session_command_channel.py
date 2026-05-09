from core.protocol.message_types import MSG_TYPE_COMMAND, MSG_TYPE_CANCEL


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

    def build_command_payload(self, command: str, command_type: str = MSG_TYPE_COMMAND, extra=None) -> dict:
        data = {
            'type': command_type,
            'id': self.generate_message_id(),
            'text': command,
        }
        if extra:
            data['extra'] = extra
        return data

    def build_cancel_payload(self, target_command_id: int) -> dict:
        return {
            'type': MSG_TYPE_CANCEL,
            'id': self.generate_message_id(),
            'target_id': target_command_id,
        }

    def send_command(self, command: str, type=MSG_TYPE_COMMAND, extra=None, history_entry_id: str = ''):
        data = self.build_command_payload(command, type, extra)

        history_orchestrator = getattr(self.session.context, 'command_history_orchestrator', None)

        bound_task = self.session.runtime.bind_command_execution(
            data.get('id'),
            session=self.session,
            history_entry_id=history_entry_id,
            history_orchestrator=history_orchestrator,
        )
        self.session.send(data)

        if bound_task and bound_task.get('cancel_requested'):
            self.send_cancel(data.get('id'))

        return self.wait_for_result(data.get('id'), command if type == MSG_TYPE_COMMAND else None)

    def send_cancel(self, target_command_id: int):
        data = self.build_cancel_payload(target_command_id)
        self.session.send(data)
        return data

    def wait_for_result(self, command_id: int, command: str = ''):
        yield from self.session.runtime.wait_for_result(self.session, command_id, command)









