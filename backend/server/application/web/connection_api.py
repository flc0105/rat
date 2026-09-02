class WebConnectionApi:
    """
    Web 连接子外观。

    职责：
    - 暴露 connection payload 查询
    - 暴露 connection 生命周期相关能力
    - 暴露面向调用方的连接序列化能力
    - 暴露 machine 级设备分组管理能力
    """

    def __init__(self, connection_service, device_group_store=None):
        self.connection_service = connection_service
        self.device_group_store = device_group_store

    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def serialize_connection(self, session):
        return self.connection_service.serialize_connection(session)

    def get_machine_connection_history(self, machine_id: str):
        return self.connection_service.get_machine_connection_history(machine_id)

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

    def _require_device_group_store(self):
        if self.device_group_store is None:
            raise ValueError('Device group store is unavailable')
        return self.device_group_store

    def get_device_groups(self):
        return self._require_device_group_store().get_state()

    def create_device_group(self, name: str):
        return self._require_device_group_store().create_group(name)

    def rename_device_group(self, group_id: str, name: str):
        return self._require_device_group_store().rename_group(group_id, name)

    def delete_device_group(self, group_id: str):
        return self._require_device_group_store().delete_group(group_id)

    def assign_machine_device_group(self, machine_id: str, group_id: str = ''):
        return self._require_device_group_store().assign_machine(machine_id, group_id)
