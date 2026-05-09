import re
import shlex
from typing import Any


VAR_PATTERN = re.compile(r'{{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*}}')


def context_get(context: dict, dotted_key: Any) -> Any:
    key = str(dotted_key or '').strip()
    if not key:
        return ''
    if key in context:
        return context[key]
    current: Any = context
    for part in key.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def render_value(value: Any, context: dict) -> Any:
    if isinstance(value, str):
        def replace(match):
            key = match.group(1)
            resolved = context_get(context, key)
            return str(resolved if resolved is not None else match.group(0))
        return VAR_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [render_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: render_value(val, context) for key, val in value.items()}
    return value


def split_extra_argv(value: Any) -> list[str]:
    if value is None or value == '':
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item or '').strip()]
    if isinstance(value, tuple):
        return [str(item) for item in value if str(item or '').strip()]
    text = str(value or '').strip()
    if not text:
        return []
    try:
        return shlex.split(text)
    except ValueError as e:
        raise ValueError(f'invalid extra argv: {e}')


def append_runtime_extra_args(argv: list[str], runtime: dict, context: dict) -> list[str]:
    result = list(argv or [])
    runtime = runtime if isinstance(runtime, dict) else {}
    extra_args = runtime.get('extra_args')
    extra_args_param = str(runtime.get('extra_args_param') or '').strip()
    if extra_args_param:
        extra_args = context.get(extra_args_param, extra_args)
    rendered_extra_args = render_value(extra_args, context)
    result.extend(split_extra_argv(rendered_extra_args))
    return result
