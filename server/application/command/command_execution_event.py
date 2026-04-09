from dataclasses import dataclass, field


@dataclass
class CommandExecutionEvent:
    STARTED = 'started'
    CHUNK = 'chunk'
    ERROR = 'error'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'

    event_type: str
    status: int | None = None
    text: str = ''
    ok: bool | None = None
    payload: dict = field(default_factory=dict)

    @classmethod
    def started(cls, command: str, payload: dict | None = None):
        return cls(cls.STARTED, payload={'command': command, **dict(payload or {})})

    @classmethod
    def chunk(cls, status: int, text: str, payload: dict | None = None):
        return cls(cls.CHUNK, status=int(status), text=str(text or ''), payload=dict(payload or {}))

    @classmethod
    def error(cls, text: str, payload: dict | None = None):
        return cls(cls.ERROR, status=0, text=str(text or ''), ok=False, payload=dict(payload or {}))

    @classmethod
    def completed(cls, ok: bool, payload: dict | None = None):
        return cls(cls.COMPLETED, status=1 if ok else 0, ok=bool(ok), payload=dict(payload or {}))

    @classmethod
    def cancelled(cls, text: str = '', payload: dict | None = None):
        return cls(cls.CANCELLED, status=0, text=str(text or ''), ok=False, payload=dict(payload or {}))