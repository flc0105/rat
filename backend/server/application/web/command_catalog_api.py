class WebCommandCatalogApi:
    """
    Web 命令候选子外观。

    职责：
    - 聚合客户端命令清单
    - 聚合服务端命令候选
    - 输出去重后的 command candidates
    """

    def __init__(self, server, command_executor_factory, remote_file_service=None):
        self.server = server
        self.command_executor_factory = command_executor_factory
        self.remote_file_service = remote_file_service

    def _get_client_command_candidates(self, session):
        payload = session.session_info.command_manifest or []
        if not isinstance(payload, list):
            return []

        result = []
        for item in payload:
            if not isinstance(item, dict):
                continue

            name = (item.get('name') or '').strip()
            template = (item.get('template') or name).strip()

            if not name or not template:
                continue

            result.append({
                'name': name,
                'template': template,
                'help': item.get('help', ''),
                'group': item.get('group', 'general'),
                'suggest': item.get('suggest', True),
                'source': item.get('source', 'client'),
            })

        return result

    def _build_cd_directory_candidate(self, item: dict) -> dict | None:
        name = str((item or {}).get('name') or '').strip()
        path = str((item or {}).get('path') or '').strip()

        if not name:
            return None

        return {
            'name': name,
            'template': f'cd {name}',
            'help': f'Change directory -> {path or name}',
            'group': 'filesystem',
            'source': 'cd_directory',
            'path': path,
        }

    def get_command_candidates(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        client_candidates = self._get_client_command_candidates(session)
        server_candidates = self.command_executor_factory.create(session).get_command_candidates()

        merged = []
        seen = set()
        for item in client_candidates + server_candidates:
            template = (item.get('template') or '').strip()
            if not template or template in seen:
                continue
            seen.add(template)
            merged.append(item)

        merged.sort(key=lambda item: (item.get('source', ''), item.get('template', '').lower()))
        return merged

    def get_cd_directory_candidates(self, client_id: str, path: str = ''):
        if self.remote_file_service is None:
            return []

        base_path = (path or '').strip()
        payload = self.remote_file_service.list_child_directories(client_id, base_path)
        entries = payload.get('entries') or []

        result = []
        for item in entries:
            if not isinstance(item, dict):
                continue

            candidate = self._build_cd_directory_candidate(item)
            if candidate:
                result.append(candidate)

        result.sort(key=lambda item: item.get('name', '').lower())
        return result
