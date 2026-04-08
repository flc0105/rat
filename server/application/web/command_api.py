class WebCommandApi:
    """
    Web 命令子外观。

    职责：
    - 提供 command candidates
    - 提供 command history / execution history 相关接口
    - 提供 Web command / upload / cancel task 提交入口

    说明：
    - 不负责 HTTP 解析
    - 不负责对象装配
    - 聚合 command/history/task submit 这一组 Web 应用动作
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

    # ------------------ command candidates ------------------ #
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
    def get_command_history(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_history_for_connection(session)

    def get_command_execution_history(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        return self.server.command_history.get_execution_history_for_connection(session)

    def clear_command_history(self, client_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        self.server.command_history.clear_history_for_connection(session)
        return None

    def set_command_history_pinned(self, client_id: str, command: str, is_pinned: bool):
        session = self.server.get_target_connection_by_client_id(client_id)
        changed = self.server.command_history.set_command_pinned_for_connection(
            session,
            command,
            is_pinned,
        )
        return {
            'command': (command or '').strip(),
            'is_pinned': bool(is_pinned),
            'changed': bool(changed),
        }

    def move_command_history_pinned(self, client_id: str, command: str, direction: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        changed = self.server.command_history.move_pinned_command_for_connection(
            session,
            command,
            direction,
        )
        return {
            'command': (command or '').strip(),
            'direction': (direction or '').strip().lower(),
            'changed': bool(changed),
        }

    def delete_command_execution_history_entry(self, client_id: str, entry_id: str):
        session = self.server.get_target_connection_by_client_id(client_id)
        deleted = self.server.command_history.delete_execution_entry_for_connection(session, entry_id)
        return {
            'entry_id': (entry_id or '').strip(),
            'deleted': bool(deleted),
        }

    # ------------------ web task submit ------------------ #
    def submit_web_command(self, client_id: str, command: str, tab_id: str = ''):
        return self.task_service.submit_web_command(client_id, command, tab_id=tab_id)

    def cancel_web_task(self, task_id: str):
        return self.task_service.cancel_web_task(task_id)

    def submit_web_upload(
        self,
        client_id: str,
        local_path: str,
        display_name: str,
        remote_path: str = '',
        tab_id: str = '',
    ):
        return self.task_service.submit_web_upload(
            client_id,
            local_path,
            display_name,
            remote_path,
            tab_id=tab_id,
        )