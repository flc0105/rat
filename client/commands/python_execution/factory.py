from client.commands.python_execution.inproc import InProcessPythonExecutionStrategy
from client.commands.python_execution.subprocess_pipe import SubprocessPipePythonExecutionStrategy

try:
    from client.config.runtime_config import PYTHON_EXECUTION_MODE
except Exception:
    PYTHON_EXECUTION_MODE = 'inproc'


def normalize_python_execution_mode(mode: str = '') -> str:
    normalized = str(mode or '').strip().lower()
    if normalized in ('inproc', 'subprocess_pipe'):
        return normalized

    normalized_default = str(PYTHON_EXECUTION_MODE or '').strip().lower()
    if normalized_default in ('inproc', 'subprocess_pipe'):
        return normalized_default

    return 'inproc'


def build_python_execution_strategy(owner, mode: str = ''):
    normalized = normalize_python_execution_mode(mode)
    if normalized == 'subprocess_pipe':
        return SubprocessPipePythonExecutionStrategy(owner)
    return InProcessPythonExecutionStrategy(owner)