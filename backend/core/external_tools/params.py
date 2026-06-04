from typing import Any

_REMOTE_PATH_PARAM_TYPES = {
    'remote_file',
    'remote_folder',
}
_REMOTE_PATH_MULTI_PARAM_TYPES = {
    'remote_files',
    'remote_folders',
}


def _coerce_path_list(value: Any, param_name: str) -> list[str]:
    if value is None or value == '':
        return []

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        return [item.strip() for item in text.split(',') if item.strip()]

    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f'param {param_name} must be a path list')

    result = []
    for item in value:
        text = str(item or '').strip()
        if text:
            result.append(text)
    return result


def coerce_param_value(spec: dict, value: Any, require_required: bool = True) -> Any:
    source = spec if isinstance(spec, dict) else {}
    param_name = source.get('name') or 'param'
    param_type = str(source.get('type') or 'string').strip().lower()
    if value is None or value == '':
        if source.get('default') is not None:
            value = source.get('default')
        elif source.get('required') and require_required:
            raise ValueError(f'param {param_name} is required')
        else:
            return [] if param_type in _REMOTE_PATH_MULTI_PARAM_TYPES else ''
    if param_type in ('int', 'integer', 'number'):
        try:
            return int(value)
        except Exception:
            raise ValueError(f'param {param_name} must be an integer')
    if param_type in ('bool', 'boolean'):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ('1', 'true', 'yes', 'on')
    if param_type in _REMOTE_PATH_MULTI_PARAM_TYPES:
        return _coerce_path_list(value, str(param_name))
    if param_type in _REMOTE_PATH_PARAM_TYPES:
        if isinstance(value, (list, tuple, set)):
            path_list = _coerce_path_list(value, str(param_name))
            return path_list[0] if path_list else ''
        return str(value or '').strip()
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
