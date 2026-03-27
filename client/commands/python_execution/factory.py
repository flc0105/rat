from client.commands.python_execution.inproc import InProcessPythonExecutionStrategy
from client.commands.python_execution.subprocess_pipe import SubprocessPipePythonExecutionStrategy

try:
    from client.config.runtime_config import (
        PYTHON_EXECUTION_MODE,
        PYTHON_EXECUTION_COLLECT_MODE,
        PYTHON_EXECUTION_STREAM_MODE,
    )
except Exception:
    PYTHON_EXECUTION_MODE = 'inproc'
    PYTHON_EXECUTION_COLLECT_MODE = ''
    PYTHON_EXECUTION_STREAM_MODE = ''


def normalize_python_execution_mode(mode: str = '', default_mode: str = 'inproc') -> str:
    normalized = str(mode or '').strip().lower()
    if normalized in ('inproc', 'subprocess_pipe'):
        return normalized

    normalized_default = str(default_mode or '').strip().lower()
    if normalized_default in ('inproc', 'subprocess_pipe'):
        return normalized_default

    return 'inproc'


def get_python_collect_mode() -> str:
    explicit_mode = str(PYTHON_EXECUTION_COLLECT_MODE or '').strip()
    if explicit_mode:
        return normalize_python_execution_mode(explicit_mode, default_mode='inproc')
    return normalize_python_execution_mode(PYTHON_EXECUTION_MODE, default_mode='inproc')


def get_python_stream_mode() -> str:
    explicit_mode = str(PYTHON_EXECUTION_STREAM_MODE or '').strip()
    if explicit_mode:
        return normalize_python_execution_mode(explicit_mode, default_mode='inproc')
    return normalize_python_execution_mode(PYTHON_EXECUTION_MODE, default_mode='inproc')


def build_python_execution_strategy(owner, mode: str = '', default_mode: str = 'inproc'):
    normalized = normalize_python_execution_mode(mode, default_mode=default_mode)
    if normalized == 'subprocess_pipe':
        return SubprocessPipePythonExecutionStrategy(owner)
    return InProcessPythonExecutionStrategy(owner)