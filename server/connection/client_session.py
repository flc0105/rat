from server.connection.channel.session_command_channel import ClientSessionCommandChannel
from server.connection.context.session_context import ClientSessionContext
from server.connection.runtime.session_runtime import ClientSessionRuntime
from server.connection.services.session_services import ClientSessionServices
from server.connection.transport.client_transport import ClientTransport


class ClientSession:
    def __init__(self, transport: ClientTransport, info=None):
        self.transport = transport
        self.info = info or {}

        self.runtime = ClientSessionRuntime()
        self.context = ClientSessionContext()
        self.services = ClientSessionServices(self)
        self.command_channel = ClientSessionCommandChannel(self)

    @property
    def address(self):
        return self.transport.address

    def send(self, data: dict):
        self.transport.send(data)

    def recv(self):
        return self.transport.recv()

    def close(self):
        self.transport.close()

    def bind_history_entry(self, command_id: int, entry_id: str):
        self.runtime.bind_history_entry(command_id, entry_id)

    def get_history_entry_id(self, command_id: int) -> str:
        return self.runtime.get_history_entry_id(command_id)

    def clear_history_entry(self, command_id: int):
        self.runtime.clear_history_entry(command_id)

    def append_file_to_history(self, command_id: int, file_info: dict):
        if self.context.command_history is None:
            return

        entry_id = self.runtime.get_history_entry_id(command_id)
        if not entry_id:
            return

        try:
            self.context.command_history.append_file_for_connection(self, entry_id, file_info)
        except Exception:
            pass

    def send_command(self, command: str, type='command', extra=None, history_entry_id: str = ''):
        return self.command_channel.send_command(
            command,
            type=type,
            extra=extra,
            history_entry_id=history_entry_id
        )

    def handle_received_message(self, data: dict):
        return self.services.message_dispatcher.dispatch(data)

    def recv_message(self):
        data = self.transport.recv()
        result = self.handle_received_message(data)
        if result:
            raise RuntimeError(f'Unexpected recv_message result: {result}')

    def acquire_foreground_task(self, task_type: str, command: str, source: str = '', task_id: str = '') -> dict:
        return self.runtime.acquire_foreground_task(
            task_type=task_type,
            command=command,
            source=source,
            task_id=task_id
        )

    def release_foreground_task(self, task_id: str = '', command: str = '') -> None:
        self.runtime.release_foreground_task(task_id=task_id, command=command)

    def get_foreground_task(self):
        return self.runtime.get_foreground_task()
