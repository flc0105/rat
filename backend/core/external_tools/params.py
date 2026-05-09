from typing import Any


def coerce_param_value(spec: dict, value: Any, require_required: bool = True) -> Any:
    source = spec if isinstance(spec, dict) else {}
    param_type = str(source.get('type') or 'string').strip().lower()
    if value is None or value == '':
        if source.get('default') is not None:
            value = source.get('default')
        elif source.get('required') and require_required:
            raise ValueError(f'param {source.get("name")} is required')
        else:
            return ''
    if param_type in ('int', 'integer', 'number'):
        try:
            return int(value)
        except Exception:
            raise ValueError(f'param {source.get("name")} must be an integer')
    if param_type in ('bool', 'boolean'):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ('1', 'true', 'yes', 'on')
    return str(value)


def resolve_params(meta: dict, params: dict | None, require_required: bool = True) -> dict:
    source = params if isinstance(params, dict) else {}
    resolved = {}
    for spec in (meta.get('params') if isinstance(meta, dict) else []) or []:
        name = str(spec.get('name') or '').strip() if isinstance(spec, dict) else ''
        if not name:
            continue
        resolved[name] = coerce_param_value(spec, source.get(name), require_required=require_required)
    for key, value in source.items():
        if key not in resolved:
            resolved[key] = value
    return resolved
