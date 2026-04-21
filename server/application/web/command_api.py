class WebCommandApi:
    """
    Web 命令子外观。

    职责：
    - 提供 command candidates
    - 提供 command history / execution history 相关接口
    - 提供 Web command / upload / cancel task 提交入口
    """

    def __init__(self, server, command_executor_factory, task_service):
        self.server = server
        self.command_executor_factory = command_executor_factory
        self.task_service = task_service

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

    # ------------------ command history ------------------ #
    def get_command_history(self, machine_id: str):
        return self.server.command_history.view_service.get_history_by_machine_id(machine_id)

    def get_command_execution_history(self, machine_id: str):
        return self.server.command_history.view_service.get_execution_history_by_machine_id(machine_id)

    def clear_command_history(self, machine_id: str):
        self.server.command_history.write_service.clear_history_by_machine_id(machine_id)
        return None

    def set_command_history_pinned(self, machine_id: str, command: str, is_pinned: bool):
        changed = self.server.command_history.write_service.set_command_pinned_by_machine_id(
            machine_id,
            command,
            is_pinned,
        )
        return {
            'machine_id': (machine_id or '').strip(),
            'command': (command or '').strip(),
            'is_pinned': bool(is_pinned),
            'changed': bool(changed),
        }

    def move_command_history_pinned(self, machine_id: str, command: str, direction: str):
        changed = self.server.command_history.write_service.move_pinned_command_by_machine_id(
            machine_id,
            command,
            direction,
        )
        return {
            'machine_id': (machine_id or '').strip(),
            'command': (command or '').strip(),
            'direction': (direction or '').strip().lower(),
            'changed': bool(changed),
        }

    def delete_command_execution_history_entry(self, machine_id: str, entry_id: str):
        deleted = self.server.command_history.write_service.delete_execution_entry_by_machine_id(machine_id, entry_id)
        return {
            'machine_id': (machine_id or '').strip(),
            'entry_id': (entry_id or '').strip(),
            'deleted': bool(deleted),
        }

    def _normalize_client_id(self, client_id: str) -> str:
        value = (client_id or '').strip()
        if not value:
            raise ValueError('client_id is required')
        return value

    def _normalize_task_id(self, task_id: str) -> str:
        value = (task_id or '').strip()
        if not value:
            raise ValueError('task_id is required')
        return value

    def _normalize_command(self, command: str) -> str:
        value = (command or '').strip()
        if not value:
            raise ValueError('command is required')
        return value

    def _normalize_upload_payload(self, local_path: str, display_name: str, remote_path: str = '') -> dict:
        normalized_local_path = (local_path or '').strip()
        normalized_display_name = (display_name or '').strip()
        if not normalized_local_path:
            raise ValueError('local_path is required')
        if not normalized_display_name:
            raise ValueError('display_name is required')

        return {
            'local_path': normalized_local_path,
            'display_name': normalized_display_name,
            'remote_path': (remote_path or '').strip(),
        }

    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.task_service.submit_web_command(
            self._normalize_client_id(client_id),
            self._normalize_command(command),
            tab_id=(tab_id or '').strip(),
        )

    def cancel_web_task(self, task_id: str):
        return self.task_service.cancel_web_task(self._normalize_task_id(task_id))

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str, remote_path: str = '', tab_id: str = ''):
        upload_payload = self._normalize_upload_payload(local_path, display_name, remote_path)
        return self.task_service.submit_web_upload(
            self._normalize_client_id(client_id),
            upload_payload['local_path'],
            upload_payload['display_name'],
            upload_payload['remote_path'],
            tab_id=(tab_id or '').strip(),
        )