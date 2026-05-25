from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScriptSdkRuntimeContext:
    """
    Script SDK 当前执行上下文。

    只保存脚本运行期需要的轻量对象：
    - command_owner：当前平台命令实例，inproc 模式可复用既有命令能力
    - kwargs：server script 参数
    - script_context：CommandExecutionMixin 注入的 __context__
    """

    command_owner: Any = None
    kwargs: dict = field(default_factory=dict)
    script_context: dict = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.script_context.get(key, default)


_current_context: ContextVar[ScriptSdkRuntimeContext | None] = ContextVar(
    'script_sdk_runtime_context',
    default=None,
)


def _safe_dict(value) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def get_current_context() -> ScriptSdkRuntimeContext:
    context = _current_context.get()
    if context is None:
        return ScriptSdkRuntimeContext()
    return context


def get_command_owner():
    return get_current_context().command_owner


def get_script_context() -> dict:
    return dict(get_current_context().script_context)


def get_client_id() -> str:
    return str(get_current_context().get('client_id', '') or '')


def get_command_id():
    command_id = get_current_context().get('command_id', '')
    return command_id if command_id != '' else None


@contextmanager
def use_script_sdk_context(command_owner=None, kwargs=None):
    payload = _safe_dict(kwargs)
    script_context = _safe_dict(payload.get('__context__'))
    token = _current_context.set(
        ScriptSdkRuntimeContext(
            command_owner=command_owner,
            kwargs=payload,
            script_context=script_context,
        )
    )
    try:
        yield
    finally:
        _current_context.reset(token)


def _iter_exported_command_names(command_owner):
    if command_owner is None:
        return []

    names = []
    for name in dir(command_owner):
        if not name or name.startswith('_'):
            continue
        try:
            func = getattr(command_owner, name)
        except Exception:
            continue
        if callable(func) and hasattr(func, 'help'):
            names.append(name)
    return sorted(set(names))


def build_script_sdk_globals(command_owner=None, kwargs=None) -> dict:
    """
    构造注入到 server script 的 SDK 全局变量。
    """
    from client.runtime.sdk import artifact, command, keychains

    sdk_globals = {
        'artifact': artifact,
        'command': command,
        'keychains': keychains,
    }

    for name in _iter_exported_command_names(command_owner):
        if name in sdk_globals or name in {'kwargs', '__context__'}:
            continue
        sdk_globals[name] = command.build_client_command_function(name)

    return sdk_globals
