import inspect
import json

from client.commands.common.services.completion.command_completion_service import ClientCommandCompletionService
from core.utils.decorator import desc


class CommandIntrospectionMixin:

    @property
    def command_completion_service(self):
        service = getattr(self, '_command_completion_service', None)
        if service is None:
            service = ClientCommandCompletionService(self)
            self._command_completion_service = service
        return service

    def _get_exported_command_methods(self):
        """
        获取所有可导出的命令方法
        """
        return {
            name: method
            for name, method in inspect.getmembers(
                self,
                lambda x: inspect.isfunction(x) or inspect.ismethod(x)
            )
            if hasattr(method, 'help')
        }

    def _get_argument_command_registry(self):
        """
        获取 acmd 注册表
        """
        getter = getattr(self, 'get_argument_command_registry', None)
        if callable(getter):
            registry = getter()
            if registry is not None:
                return registry

        from client.commands.arguments.registry import ArgumentCommandRegistry
        return ArgumentCommandRegistry(self)

    def _get_argument_command_manifest_payload(self):
        """
        获取 acmd 自动补全清单
        """
        try:
            registry = self._get_argument_command_registry()
            return registry.get_manifest_payload()
        except Exception:
            return []

    def _get_argument_command_help_items(self):
        """
        获取 acmd help 分组项
        """
        try:
            registry = self._get_argument_command_registry()
            entries = registry.list_command_entries()
            return [
                (f'acmd {item.get("name", "")}', item.get('description') or 'No description')
                for item in entries
                if item.get('name')
            ]
        except Exception:
            return []

    def get_command_manifest_payload(self):
        """
        获取命令清单数据（本地方法，不通过 socket 返回）
        """
        methods = self._get_exported_command_methods()
        payload = [
            {
                'name': name,
                'help': method.help,
                'group': getattr(method, 'group', 'general'),
                'suggest': getattr(method, 'suggest', True),
            }
            for name, method in methods.items()
        ]

        payload.extend(self._get_argument_command_manifest_payload())
        payload.sort(key=lambda item: (item.get('group', 'general'), item.get('name', '').lower()))
        return payload

    def _group_command_help_payload(self):
        """
        将命令按 group 分组，生成 help 文本结构
        """
        methods = self._get_exported_command_methods()
        grouped = {}

        for name, method in methods.items():
            # suggest=False 的内部命令不在 help 中展示，但仍保留执行能力。
            if not getattr(method, 'suggest', True):
                continue
            group = getattr(method, 'group', 'general')
            grouped.setdefault(group, []).append((name, method.help))

        argument_command_items = self._get_argument_command_help_items()
        if argument_command_items:
            grouped.setdefault('acmd', []).extend(argument_command_items)

        for group_name in grouped:
            grouped[group_name].sort(key=lambda item: item[0].lower())

        return grouped


    @desc('Resolve command autocomplete candidates', group='session', suggest=False)
    def command_completions(self, arg=''):
        """
        command bar 只读补全入口。
        """
        try:
            payload = self.structured_arg_codec.decode(arg)
            if not isinstance(payload, dict):
                payload = {}
            result_payload = self.command_completion_service.complete(payload)
            return 1, json.dumps(result_payload, ensure_ascii=False)
        except Exception as e:
            return 0, f'Failed to resolve command completions: {e}'

    @desc('Show available commands', group='session')
    def help(self):
        grouped = self._group_command_help_payload()
        if not grouped:
            return 1, ''

        title_map = {
            'shell': 'Shell / Execution',
            'file': 'File',
            'file_path': 'File Path / Web',
            'job': 'Job',
            'session': 'Session',
            'platform': 'Platform',
            'acmd': 'Acmd',
            'general': 'General',
        }

        lines = []
        ordered_groups = ['shell', 'file', 'file_path', 'job', 'session', 'platform', 'acmd', 'general']
        seen = set()

        for group_name in ordered_groups:
            items = grouped.get(group_name)
            if not items:
                continue

            seen.add(group_name)
            lines.append(f'[{title_map.get(group_name, group_name)}]')
            for name, help_text in items:
                lines.append(f'{name:<24}{help_text}')
            lines.append('')

        for group_name, items in grouped.items():
            if group_name in seen:
                continue

            lines.append(f'[{title_map.get(group_name, group_name)}]')
            for name, help_text in items:
                lines.append(f'{name:<24}{help_text}')
            lines.append('')

        return 1, '\n'.join(lines).rstrip()








