from core.command_completion.models import CompletionCandidate, CompletionContext
from core.command_completion.provider import CommandCompletionProvider


class CommandCompletionRegistry:
    """
    CommandCompletionProvider 注册表。
    """

    def __init__(self, providers: list[CommandCompletionProvider] | None = None):
        self._providers: list[CommandCompletionProvider] = []
        for provider in providers or []:
            self.register(provider)

    def register(self, provider: CommandCompletionProvider):
        if not isinstance(provider, CommandCompletionProvider):
            raise TypeError('provider must be CommandCompletionProvider')
        self._providers.append(provider)
        return provider

    def complete(self, context: CompletionContext) -> list[CompletionCandidate]:
        result: list[CompletionCandidate] = []
        for provider in self._providers:
            try:
                if not provider.supports(context):
                    continue
                result.extend(provider.complete(context))
            except Exception:
                # autocomplete 不能因为单个 provider 失败影响整条命令输入链路。
                continue

        return self._dedupe(result)

    def _dedupe(self, candidates: list[CompletionCandidate]) -> list[CompletionCandidate]:
        seen = set()
        result = []
        for candidate in candidates:
            key = (candidate.insert_text or candidate.title or '').strip()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(candidate)
        result.sort(key=lambda item: (item.priority, item.title.lower()))
        return result
