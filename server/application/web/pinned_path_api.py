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

    # add machine_id quick jump 存储 2026-04-09 15:30
    def _get_session(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    # add machine_id quick jump 存储 2026-04-09 15:30
    def _get_machine_id(self, client_id: str) -> str:
        session = self._get_session(client_id)
        session_info = getattr(session, 'session_info', None)
        return getattr(session_info, 'machine_id', '') or 'unknown_machine'

    # add machine_id quick jump 存储 2026-04-09 15:30
    def list_pinned_paths(self, client_id: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        return {
            'machine_id': machine_id,
            'items': self.pinned_path_store.list_items(machine_id),
        }

    # add machine_id quick jump 存储 2026-04-09 15:30
    def save_pinned_paths(self, client_id: str, display_name: str, path: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.save_item(machine_id, display_name, path)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Saved quick jump: {item.get("display_name", "")}',
        }

    # add quick jump 管理编辑 2026-04-09 16:20
    def update_pinned_path(self, client_id: str, original_display_name: str, display_name: str, path: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.update_item(machine_id, original_display_name, display_name, path)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Updated quick jump: {item.get("display_name", "")}',
        }

    # add machine_id quick jump 存储 2026-04-09 15:30
    def delete_pinned_path(self, client_id: str, display_name: str) -> dict:
        machine_id = self._get_machine_id(client_id)
        item = self.pinned_path_store.delete_item(machine_id, display_name)
        return {
            'machine_id': machine_id,
            'item': item,
            'items': self.pinned_path_store.list_items(machine_id),
            'message': f'Removed quick jump: {item.get("display_name", "")}',
        }
