class PinnedPathApi:
    """
    Web quick jump 子外观。

    职责：
    - 按 client_id 解析 machine_id
    - 提供 machine_id 级 quick jump 收藏查询 / 保存 / 删除
    """

    def __init__(self, server, pinned_path_store):
        self.server = server
        self.pinned_path_store = pinned_path_store


    def _get_session(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)


    def _get_machine_id(self, client_id: str) -> str:
        session = self._get_session(client_id)
        session_info = getattr(session, 'session_info', None)
        return getattr(session_info, 'machine_id', '') or 'unknown_machine'


    def list_pinned_paths(self, client_id: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        return {
            'machine_id': machine_id,
            'items': self.pinned_path_store.list_items(machine_id),
        }


    def save_pinned_paths(self, client_id: str, display_name: str, path: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.save_item(machine_id, display_name, path)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Saved quick jump: {item.get("display_name", "")}',
        }


    def update_pinned_path(self, client_id: str, original_display_name: str, display_name: str, path: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.update_item(machine_id, original_display_name, display_name, path)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Updated quick jump: {item.get("display_name", "")}',
        }


    def delete_pinned_path(self, client_id: str, display_name: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.delete_item(machine_id, display_name)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Removed quick jump: {item.get("display_name", "")}',
        }
