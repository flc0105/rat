from server.application.keychains.keychain_store import KeychainStore


class WebKeychainApi:
    """
    Web 凭证管理子外观。

    说明：
    - 凭证只保存在服务端 runtime/keychains JSON 中
    - 不向 client 下发任何指令，也不依赖 client 执行
    - 列表默认不返回 secret_value，查看 / 编辑时才读取明文
    """

    def __init__(self, server, keychain_store: KeychainStore, connection_service):
        self.server = server
        self.keychain_store = keychain_store
        self.connection_service = connection_service

    def _safe_text(self, value) -> str:
        return '' if value is None else str(value).strip()

    def _normalize_machine_id(self, machine_id: str) -> str:
        return self._safe_text(machine_id) or KeychainStore.SERVER_MACHINE_ID

    def _normalize_hostname(self, machine_id: str, hostname: str) -> str:
        normalized_machine_id = self._normalize_machine_id(machine_id)
        if normalized_machine_id == KeychainStore.SERVER_MACHINE_ID:
            return KeychainStore.SERVER_HOSTNAME
        return self._safe_text(hostname) or 'Unknown'

    def _connection_machines(self) -> list[dict]:
        machines = {}
        try:
            connections = self.connection_service.get_connections_payload()
        except Exception:
            connections = []

        for item in connections:
            if not isinstance(item, dict):
                continue
            machine_id = self._safe_text(item.get('machine_id'))
            if not machine_id:
                continue
            machines[machine_id] = {
                'machine_id': machine_id,
                'hostname': self._safe_text(item.get('hostname')) or 'Unknown',
                'connection_state': self._safe_text(item.get('connection_state')) or 'offline',
            }
        return list(machines.values())

    def list_machines(self) -> list[dict]:
        machine_map = {
            KeychainStore.SERVER_MACHINE_ID: {
                'machine_id': KeychainStore.SERVER_MACHINE_ID,
                'hostname': KeychainStore.SERVER_HOSTNAME,
                'connection_state': 'server',
            }
        }

        for item in self._connection_machines():
            machine_id = self._safe_text(item.get('machine_id'))
            if not machine_id:
                continue
            machine_map[machine_id] = item

        for item in self.keychain_store.list_stored_machines():
            machine_id = self._safe_text(item.get('machine_id'))
            if not machine_id:
                continue
            existing = machine_map.get(machine_id, {})
            machine_map[machine_id] = {
                'machine_id': machine_id,
                'hostname': self._safe_text(existing.get('hostname')) or self._safe_text(item.get('hostname')) or 'Unknown',
                'connection_state': self._safe_text(existing.get('connection_state')) or 'offline',
            }

        def _sort_key(item):
            machine_id = self._safe_text(item.get('machine_id'))
            if machine_id == KeychainStore.SERVER_MACHINE_ID:
                return (0, 'server')
            return (1, self._safe_text(item.get('hostname')).lower(), machine_id.lower())

        return sorted(machine_map.values(), key=_sort_key)

    def _resolve_hostname(self, machine_id: str, requested_hostname: str = '') -> str:
        normalized_machine_id = self._normalize_machine_id(machine_id)
        if requested_hostname:
            return self._normalize_hostname(normalized_machine_id, requested_hostname)

        for item in self.list_machines():
            if self._safe_text(item.get('machine_id')) == normalized_machine_id:
                return self._normalize_hostname(normalized_machine_id, item.get('hostname'))
        return self._normalize_hostname(normalized_machine_id, '')

    def _normalize_payload(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError('payload is required')

        normalized = dict(payload)
        machine_id = self._normalize_machine_id(normalized.get('machine_id'))
        normalized['machine_id'] = machine_id
        normalized['hostname'] = self._resolve_hostname(machine_id, normalized.get('hostname') or '')
        return normalized

    def _is_server_scope(self, value: str) -> bool:
        return self._safe_text(value).lower() in {'server', KeychainStore.SERVER_MACHINE_ID}

    def _normalize_script_create_payload(self, payload: dict, script_grant: dict) -> dict:
        """
        Script grant 创建凭证时只允许写当前 client machine 或 server。
        Web session/admin 创建仍走 _normalize_payload，保持原管理能力。
        """
        if not isinstance(payload, dict):
            raise ValueError('payload is required')
        if not isinstance(script_grant, dict) or not script_grant:
            return self._normalize_payload(payload)

        normalized = dict(payload)
        own_machine_id = self._safe_text(script_grant.get('machine_id'))
        own_hostname = self._safe_text(script_grant.get('hostname'))
        requested_scope = self._safe_text(normalized.get('scope'))
        requested_machine_id = self._safe_text(normalized.get('machine_id'))

        if self._is_server_scope(requested_scope) or self._is_server_scope(requested_machine_id):
            normalized['machine_id'] = KeychainStore.SERVER_MACHINE_ID
            normalized['hostname'] = KeychainStore.SERVER_HOSTNAME
            return self._normalize_payload(normalized)

        if not own_machine_id:
            raise PermissionError('Script grant is missing current machine id')

        # 脚本默认写当前 client machine，不能沿用 Web 管理端的默认 server。
        if not requested_machine_id:
            normalized['machine_id'] = own_machine_id
            if own_hostname and not self._safe_text(normalized.get('hostname')):
                normalized['hostname'] = own_hostname
            return self._normalize_payload(normalized)

        if requested_machine_id != own_machine_id:
            raise PermissionError('Script grant can only create keychains for current machine or server')

        normalized['machine_id'] = own_machine_id
        if own_hostname and not self._safe_text(normalized.get('hostname')):
            normalized['hostname'] = own_hostname
        return self._normalize_payload(normalized)


    def list_keychains(self, machine_id: str = '') -> dict:
        normalized_machine_id = self._safe_text(machine_id)
        return {
            'items': self.keychain_store.list_items(normalized_machine_id, reveal=False),
            'machines': self.list_machines(),
            'server_machine_id': KeychainStore.SERVER_MACHINE_ID,
            'server_hostname': KeychainStore.SERVER_HOSTNAME,
        }

    def get_keychain_item(self, cred_id: str) -> dict:
        item = self.keychain_store.get_item(cred_id, reveal=True)
        return {
            'item': item,
            'machines': self.list_machines(),
        }

    def resolve_keychain_item(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError('payload is required')

        name = self._safe_text(payload.get('name'))
        kind = self._safe_text(payload.get('kind')).lower()
        scope = self._safe_text(payload.get('scope')).lower()
        machine_id = self._safe_text(payload.get('machine_id'))

        if not name:
            raise ValueError('name is required')
        if kind and kind not in {KeychainStore.KIND_LOGIN, KeychainStore.KIND_SECRET}:
            raise ValueError('kind must be login or secret')

        if scope in ('server', KeychainStore.SERVER_MACHINE_ID):
            machine_id = KeychainStore.SERVER_MACHINE_ID
        else:
            machine_id = self._normalize_machine_id(machine_id)

        item = self.keychain_store.get_item_by_name(machine_id, name, kind=kind, reveal=True)
        return {
            'item': item,
            'server_machine_id': KeychainStore.SERVER_MACHINE_ID,
            'server_hostname': KeychainStore.SERVER_HOSTNAME,
        }

    def create_keychain_item(self, payload: dict, *, script_grant: dict | None = None) -> dict:
        if script_grant:
            normalized_payload = self._normalize_script_create_payload(payload, script_grant)
        else:
            normalized_payload = self._normalize_payload(payload)
        item = self.keychain_store.create_item(normalized_payload)
        return {
            'item': self.keychain_store.public_item(item),
            'items': self.keychain_store.list_items(item.get('machine_id') or '', reveal=False),
            'machines': self.list_machines(),
            'message': f'Saved credential: {item.get("name", "")}',
        }

    def update_keychain_item(self, cred_id: str, payload: dict) -> dict:
        item = self.keychain_store.update_item(cred_id, self._normalize_payload(payload))
        return {
            'item': self.keychain_store.public_item(item),
            'items': self.keychain_store.list_items(item.get('machine_id') or '', reveal=False),
            'machines': self.list_machines(),
            'message': f'Updated credential: {item.get("name", "")}',
        }

    def delete_keychain_item(self, cred_id: str) -> dict:
        item = self.keychain_store.delete_item(cred_id)
        return {
            'item': self.keychain_store.public_item(item),
            'items': self.keychain_store.list_items(item.get('machine_id') or '', reveal=False),
            'machines': self.list_machines(),
            'message': f'Deleted credential: {item.get("name", "")}',
        }
