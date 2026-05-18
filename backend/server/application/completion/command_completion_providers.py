
from core.command_completion.provider import CommandCompletionProvider
from core.command_completion.models import CompletionCandidate, CompletionContext


class GopinCommandCompletionProvider(CommandCompletionProvider):
    """
    server gopin 命令 quick jump 补全。
    """

    command_names = ('gopin',)
    source = 'server_gopin'
    group = 'quick_jump'

    def __init__(self, server, pinned_path_store):
        self.server = server
        self.pinned_path_store = pinned_path_store

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        client_id = str((context.metadata or {}).get('client_id') or '').strip()
        machine_id = self._get_machine_id(client_id)
        items = self.pinned_path_store.list_items(machine_id)

        result = []
        for item in items:
            display_name = str(item.get('display_name') or '').strip()
            target_path = str(item.get('path') or '').strip()
            if not display_name or not target_path:
                continue

            insert_text = f'gopin {display_name}'
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=f'Quick jump -> {target_path}',
                source=self.source,
                group=self.group,
                kind='quick_jump',
                name=display_name,
                priority=10,
                metadata={
                    'path': target_path,
                    'displayName': display_name,
                },
            ))

        return result

    def _get_machine_id(self, client_id: str) -> str:
        if not client_id:
            return 'unknown_machine'
        session = self.server.get_target_connection_by_client_id(client_id)
        session_info = getattr(session, 'session_info', None)
        return getattr(session_info, 'machine_id', '') or 'unknown_machine'


class RemoteClientCommandCompletionProvider(CommandCompletionProvider):
    """
    代理 client 侧 CommandCompletionProvider。
    """

    command_names = ('cd', 'set')
    source = 'client'
    group = 'client'

    def __init__(self, remote_execution_service):
        self.remote_execution_service = remote_execution_service

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        client_id = str((context.metadata or {}).get('client_id') or '').strip()
        if not client_id:
            return []

        payload = self._build_client_payload(context)
        result_payload = self.remote_execution_service.run_foreground_json_command(
            client_id,
            self._build_command(payload),
            task_type='command_candidate',
            source='web_command_autocomplete',
        )
        items = result_payload.get('items') if isinstance(result_payload, dict) else []
        return [self._candidate_from_payload(item) for item in items if isinstance(item, dict)]

    def _build_client_payload(self, context: CompletionContext) -> dict:
        payload = context.to_dict()
        metadata = dict(payload.get('metadata') or {})
        # client 侧只需要纯补全上下文，不需要 server-only 信息。
        metadata.pop('client_id', None)
        payload['metadata'] = metadata
        return payload

    def _build_command(self, payload: dict) -> str:
        import base64
        import json

        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'command_completions __json__:{encoded}'

    def _candidate_from_payload(self, item: dict) -> CompletionCandidate:
        title = str(item.get('title') or item.get('template') or item.get('value') or item.get('name') or '').strip()
        insert_text = str(item.get('insert_text') or item.get('template') or item.get('value') or title).strip()
        metadata = {
            key: value
            for key, value in item.items()
            if key not in {
                'name', 'title', 'template', 'value', 'insert_text', 'help',
                'group', 'source', 'kind', 'priority'
            }
        }
        return CompletionCandidate(
            title=title,
            insert_text=insert_text,
            description=str(item.get('help') or '').strip(),
            source=str(item.get('source') or self.source).strip(),
            group=str(item.get('group') or self.group).strip(),
            kind=str(item.get('kind') or 'command').strip(),
            name=str(item.get('name') or title).strip(),
            priority=int(item.get('priority') or 100),
            metadata=metadata,
        )
