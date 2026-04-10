class PinnedPathApi:
    """
    Web quick jump 子外观。

    职责：
    - 按 client_id 解析 hostname
    - 提供 hostname 级 quick jump 收藏查询 / 保存 / 删除
    """

    def __init__(self, server, pinned_path_store):
        self.server = server
        self.pinned_path_store = pinned_path_store

    # add hostname quick jump 存储 2026-04-09 15:30
    def _get_session(self, client_id: str):
        return self.server.get_target_connection_by_client_id(client_id)

    # add hostname quick jump 存储 2026-04-09 15:30
    def _get_hostname(self, client_id: str) -> str:
        session = self._get_session(client_id)
        session_info = getattr(session, 'session_info', None)
        return getattr(session_info, 'hostname', '') or 'unknown_host'

    # add hostname quick jump 存储 2026-04-09 15:30
    def list_pinned_paths(self, client_id: str) -> dict:
        hostname = self._get_hostname(client_id)
        return {
            'hostname': hostname,
            'items': self.pinned_path_store.list_items(hostname),
        }

    # add hostname quick jump 存储 2026-04-09 15:30
    def save_pinned_paths(self, client_id: str, display_name: str, path: str) -> dict:
        hostname = self._get_hostname(client_id)
        item = self.pinned_path_store.save_item(hostname, display_name, path)
        return {
            'hostname': hostname,
            'item': item,
            'items': self.pinned_path_store.list_items(hostname),
            'message': f'Saved quick jump: {item.get("display_name", "")}',
        }

    # add quick jump 管理编辑 2026-04-09 16:20
    def update_pinned_path(self, client_id: str, original_display_name: str, display_name: str, path: str) -> dict:
        hostname = self._get_hostname(client_id)
        item = self.pinned_path_store.update_item(hostname, original_display_name, display_name, path)
        return {
            'hostname': hostname,
            'item': item,
            'items': self.pinned_path_store.list_items(hostname),
            'message': f'Updated quick jump: {item.get("display_name", "")}',
        }

    # add hostname quick jump 存储 2026-04-09 15:30
    def delete_pinned_path(self, client_id: str, display_name: str) -> dict:
        hostname = self._get_hostname(client_id)
        item = self.pinned_path_store.delete_item(hostname, display_name)
        return {
            'hostname': hostname,
            'item': item,
            'items': self.pinned_path_store.list_items(hostname),
            'message': f'Removed quick jump: {item.get("display_name", "")}',
        }
