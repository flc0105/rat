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
    def get_command_history(self, hostname: str):
        return self.server.command_history.view_service.get_history_by_hostname(hostname)

    def get_command_execution_history(self, hostname: str):
        return self.server.command_history.view_service.get_execution_history_by_hostname(hostname)

    def clear_command_history(self, hostname: str):
        self.server.command_history.write_service.clear_history_by_hostname(hostname)
        return None

    def set_command_history_pinned(self, hostname: str, command: str, is_pinned: bool):
        changed = self.server.command_history.write_service.set_command_pinned_by_hostname(
            hostname,
            command,
            is_pinned,
        )
        return {
            'hostname': (hostname or '').strip(),
            'command': (command or '').strip(),
            'is_pinned': bool(is_pinned),
            'changed': bool(changed),
        }

    def move_command_history_pinned(self, hostname: str, command: str, direction: str):
        changed = self.server.command_history.write_service.move_pinned_command_by_hostname(
            hostname,
            command,
            direction,
        )
        return {
            'hostname': (hostname or '').strip(),
            'command': (command or '').strip(),
            'direction': (direction or '').strip().lower(),
            'changed': bool(changed),
        }

    def delete_command_execution_history_entry(self, hostname: str, entry_id: str):
        deleted = self.server.command_history.write_service.delete_execution_entry_by_hostname(hostname, entry_id)
        return {
            'hostname': (hostname or '').strip(),
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
