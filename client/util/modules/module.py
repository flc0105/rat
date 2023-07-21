class Module:
    def __init__(self):
        self.server = None
        self.command_id = None
        self.status = False

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            setattr(cls, 'instance', cls())
        return getattr(cls, 'instance')

    def set_args(self, server, command_id):
        self.server = server
        self.command_id = command_id

    def send_to_server(self, status, result, end):
        self.server.send_result(self.command_id, status, result, end)

    def run(self):
        pass

    def stop(self):
        self.send_to_server(0, f'Trying to stop...', 0)
        self.status = False
