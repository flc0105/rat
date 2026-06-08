class WebConnectionApi:
    """
    Web 连接子外观。

    职责：
    - 暴露 connection payload 查询
    - 暴露 connection 生命周期相关能力
    - 暴露面向调用方的连接序列化能力
    """

    def __init__(self, connection_service):
        self.connection_service = connection_service

    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def serialize_connection(self, session):
        return self.connection_service.serialize_connection(session)

    def create_web_connection(self, transport, addr, info: dict):
        return self.connection_service.create_web_connection(transport, addr, info)

    def handle_connection_registered(self, session):
        self.connection_service.handle_connection_registered(session)

    def handle_connection_closed(self, session):
        self.connection_service.handle_connection_closed(session)

    def remove_connection(self, client_id: str, machine_id: str = ''):
        return self.connection_service.remove_connection(client_id, machine_id=machine_id)


    def update_connection_device_view_prefs(self, client_id: str = '', machine_id: str = '', patch: dict = None):
        return self.connection_service.update_connection_device_view_prefs(
            client_id=client_id,
            machine_id=machine_id,
            patch=patch or {},
        )
