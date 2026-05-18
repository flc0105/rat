from abc import ABC, abstractmethod

from core.command_completion.models import CompletionCandidate, CompletionContext


class CommandCompletionProvider(ABC):
    """
    命令补全提供器基类。

    provider 必须无副作用，只返回 candidates，不执行真实业务命令。
    """

    command_names: tuple[str, ...] = ()
    source: str = ''
    group: str = ''

    def supports(self, context: CompletionContext) -> bool:
        command_name = str(context.command_name or '').strip().lower()
        return bool(command_name and command_name in self.command_names)

    @abstractmethod
    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        raise NotImplementedError
