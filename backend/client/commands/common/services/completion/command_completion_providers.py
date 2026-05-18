from core.command_completion.models import CompletionCandidate, CompletionContext
from core.command_completion.provider import CommandCompletionProvider


class FileSystemChildPathCommandCompletionProvider(CommandCompletionProvider):
    """
    client 文件系统子项补全基类。
    """

    source = 'client_filesystem'
    group = 'filesystem'
    entry_kind = 'path'
    command_names: tuple[str, ...] = ()

    def __init__(self, path_resolver, file_system_service):
        self.path_resolver = path_resolver
        self.file_system_service = file_system_service

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        path_parts = self._split_path_argument(context.argument_text)
        lookup_path = path_parts['lookup_path']
        candidate_prefix = path_parts['candidate_prefix']

        directory = self.path_resolver.require_existing_directory_from_arg(lookup_path)
        payload = self.list_entries(directory)
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
            insert_text = self.build_insert_text(candidate_path)
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=self.build_description(path or candidate_path),
                source=self.source,
                group=self.group,
                kind=self.entry_kind,
                name=name,
                priority=10,
                metadata={
                    'path': path,
                    'candidatePath': candidate_path,
                    'lookupPath': lookup_path,
                },
            ))

        return result

    def list_entries(self, directory: str) -> dict:
        raise NotImplementedError

    def build_insert_text(self, candidate_path: str) -> str:
        raise NotImplementedError

    def build_description(self, path: str) -> str:
        return path

    def _split_path_argument(self, argument_text: str) -> dict:
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
                # 输入 a/b/ 时，候选子项应来自 a/b。
                'lookup_path': text,
                'candidate_prefix': text,
            }

        return {
            # 输入 a/bc 时，候选子项应来自 a，并用 bc 做前端本地过滤。
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


class CdDirectoryCommandCompletionProvider(FileSystemChildPathCommandCompletionProvider):
    """
    client cd 命令目录补全。
    """

    command_names = ('cd',)
    source = 'client_cd'
    entry_kind = 'directory'

    def list_entries(self, directory: str) -> dict:
        return self.file_system_service.list_child_directories(directory)

    def build_insert_text(self, candidate_path: str) -> str:
        return f'cd {candidate_path}'.strip()

    def build_description(self, path: str) -> str:
        return f'Change directory -> {path}'


class DownloadFileCommandCompletionProvider(FileSystemChildPathCommandCompletionProvider):
    """
    client download 命令文件补全，只返回文件，不返回目录。
    """

    command_names = ('download',)
    source = 'client_download'
    entry_kind = 'file'

    def list_entries(self, directory: str) -> dict:
        return self.file_system_service.list_child_files(directory)

    def build_insert_text(self, candidate_path: str) -> str:
        return f'download {candidate_path}'.strip()

    def build_description(self, path: str) -> str:
        return f'Download file -> {path}'


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
        # 只补 set KEY value 形态，不再补 --reset / --reset-all 等管理参数。
        return self._build_config_value_candidates()

    def _build_config_value_candidates(self) -> list[CompletionCandidate]:
        result = []
        for key, value, _default_value, _source in self.runtime_config_service.list_config_items():
            value_text = self.runtime_config_service.format_value(value)
            insert_text = f'set {key} {value_text}'
            result.append(CompletionCandidate(
                title=insert_text,
                insert_text=insert_text,
                description=value_text,
                source=self.source,
                group=self.group,
                kind='runtime_config_value',
                name=key,
                priority=30,
                metadata={
                    'configKey': key,
                    'configValue': value,
                },
            ))
        return result
