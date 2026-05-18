from core.command_completion.models import CompletionCandidate, CompletionContext
from core.command_completion.provider import CommandCompletionProvider

class CdDirectoryCommandCompletionProvider(CommandCompletionProvider):
    """
    client cd 命令目录补全。
    """

    command_names = ('cd',)
    source = 'client_cd'
    group = 'filesystem'

    def __init__(self, path_resolver, file_system_service):
        self.path_resolver = path_resolver
        self.file_system_service = file_system_service

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        path_parts = self._split_directory_argument(context.argument_text)
        lookup_path = path_parts['lookup_path']
        candidate_prefix = path_parts['candidate_prefix']

        directory = self.path_resolver.require_existing_directory_from_arg(lookup_path)
        payload = self.file_system_service.list_child_directories(directory)
        entries = payload.get('entries') if isinstance(payload, dict) else []

        result = []
        for item in entries or []:
            if not isinstance(item, dict):
                continue

            name = str(item.get('name') or '').strip()
            path = str(item.get('path') or '').strip()
            if not name:
                continue

            candidate_path = f'{candidate_prefix}{name}'
            insert_text = f'cd {candidate_path}'.strip()
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=f'Change directory -> {path or candidate_path}',
                source=self.source,
                group=self.group,
                kind='directory',
                name=name,
                priority=10,
                metadata={
                    'path': path,
                    'cdCandidatePath': candidate_path,
                    'lookupPath': lookup_path,
                },
            ))

        return result

    def _split_directory_argument(self, argument_text: str) -> dict:
        text = str(argument_text or '').strip()
        if not text:
            return {
                'lookup_path': '',
                'candidate_prefix': '',
            }

        last_forward_slash_index = text.rfind('/')
        last_backward_slash_index = text.rfind('\\')
        last_separator_index = max(last_forward_slash_index, last_backward_slash_index)

        if last_separator_index < 0:
            return {
                'lookup_path': '',
                'candidate_prefix': '',
            }

        if last_separator_index == len(text) - 1:
            return {
                # 输入 cd a/b/ 时，候选目录应来自 a/b。
                'lookup_path': text,
                'candidate_prefix': text,
            }

        return {
            # 输入 cd a/bc 时，候选目录应来自 a，并用 bc 做前端本地过滤。
            'lookup_path': self._build_lookup_path_before_last_separator(text, last_separator_index),
            'candidate_prefix': text[:last_separator_index + 1],
        }

    def _build_lookup_path_before_last_separator(self, text: str, last_separator_index: int) -> str:
        if last_separator_index <= 0:
            return text[:last_separator_index + 1]

        # Windows 盘符根目录：C:\foo 应查询 C:\。
        if last_separator_index == 2 and len(text) >= 2 and text[1] == ':':
            return text[:last_separator_index + 1]

        return text[:last_separator_index]


class RuntimeConfigSetCommandCompletionProvider(CommandCompletionProvider):
    """
    client set 命令 runtime_config 补全。
    """

    command_names = ('set',)
    source = 'client_set'
    group = 'runtime'

    def __init__(self, runtime_config_service):
        self.runtime_config_service = runtime_config_service

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        items = []
        items.extend(self._build_action_candidates())
        items.extend(self._build_config_key_candidates())
        items.extend(self._build_reset_key_candidates())
        return items

    def _build_action_candidates(self) -> list[CompletionCandidate]:
        return [
            CompletionCandidate(
                title='set',
                insert_text='set',
                description='Show client runtime config items',
                source=self.source,
                group=self.group,
                kind='runtime_config',
                name='set',
                priority=20,
            ),
            CompletionCandidate(
                title='set --reset ',
                insert_text='set --reset ',
                description='Reset one runtime config key to default',
                source=self.source,
                group=self.group,
                kind='runtime_config',
                name='--reset',
                priority=21,
            ),
            CompletionCandidate(
                title='set --reset-all',
                insert_text='set --reset-all',
                description='Reset all runtime config overrides',
                source=self.source,
                group=self.group,
                kind='runtime_config',
                name='--reset-all',
                priority=21,
            ),
        ]

    def _build_config_key_candidates(self) -> list[CompletionCandidate]:
        result = []
        for key, value, default_value, source in self.runtime_config_service.list_config_items():
            insert_text = f'set {key} '
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=(
                    f'Current={self.runtime_config_service.format_value(value)}; '
                    f'default={self.runtime_config_service.format_value(default_value)}; '
                    f'source={source}'
                ),
                source=self.source,
                group=self.group,
                kind='runtime_config_key',
                name=key,
                priority=30,
                metadata={
                    'configKey': key,
                    'configValue': value,
                    'defaultValue': default_value,
                    'configSource': source,
                },
            ))
        return result

    def _build_reset_key_candidates(self) -> list[CompletionCandidate]:
        result = []
        for key, value, default_value, source in self.runtime_config_service.list_config_items():
            insert_text = f'set --reset {key}'
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=(
                    f'Reset {key} to default '
                    f'{self.runtime_config_service.format_value(default_value)}; current source={source}'
                ),
                source=self.source,
                group=self.group,
                kind='runtime_config_key',
                name=key,
                priority=31,
                metadata={
                    'configKey': key,
                    'configValue': value,
                    'defaultValue': default_value,
                    'configSource': source,
                },
            ))
        return result
