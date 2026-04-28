from dataclasses import dataclass
from typing import Any


@dataclass
class PtySession:
    """
    PTY 会话运行态。
    """

    pty_session_id: str
    backend: Any
    cols: int
    rows: int
    pid: int = 0
    closed: bool = False
    master_fd: int | None = None
    pty: Any = None
    command: str = ''
