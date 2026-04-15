import ast
from copy import deepcopy

_METADATA_KEYS = ('SCRIPT_METADATA', 'script_metadata', 'metadata', 'META', 'meta')
_ANY_PLATFORM_ALIASES = {'*', 'all', 'any'}
_PLATFORM_ALIASES = {
    'common': 'common',
    'darwin': 'darwin',
    'mac': 'darwin',
    'macos': 'darwin',
    'osx': 'darwin',
    'windows': 'windows',
    'win': 'windows',
    'win32': 'windows',
    'nt': 'windows',
    'linux': 'linux',
}
_PARAM_TYPE_ALIASES = {
    'int': 'integer',
    'integer': 'integer',
    'float': 'number',
    'number': 'number',
    'str': 'string',
    'string': 'string',
    'bool': 'boolean',
    'boolean': 'boolean',
    'select': 'select',
}


def _safe_literal_eval(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def read_script_metadata_from_source(source_text: str, fallback_name: str = '') -> dict:
    text = str(source_text or '')
    if not text.strip():
        return {}

    try:
        tree = ast.parse(text)
    except Exception:
        return {}

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _METADATA_KEYS:
                    value = _safe_literal_eval(node.value)
                    if isinstance(value, dict):
                        return normalize_script_metadata(value, fallback_name=fallback_name)
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id in _METADATA_KEYS:
                value = _safe_literal_eval(node.value)
                if isinstance(value, dict):
                    return normalize_script_metadata(value, fallback_name=fallback_name)

    return {}


def read_script_metadata_from_file(file_path: str, fallback_name: str = '') -> dict:
    try:
        with open(file_path, 'r', encoding='utf-8') as file_obj:
            return read_script_metadata_from_source(file_obj.read(), fallback_name=fallback_name)
    except Exception:
        return {}


def normalize_script_platform(value: str) -> str:
    text = str(value or '').strip().lower()
    if not text:
        return ''
    if text in _ANY_PLATFORM_ALIASES:
        return '*'
    return _PLATFORM_ALIASES.get(text, text)


def normalize_script_platforms(platforms) -> list[str]:
    if platforms is None:
        return []
    if isinstance(platforms, str):
        candidates = [platforms]
    elif isinstance(platforms, (list, tuple, set)):
        candidates = list(platforms)
    else:
        return []

    result=[]; seen=set()
    for item in candidates:
        normalized = normalize_script_platform(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _normalize_param_type(value: str) -> str:
    text = str(value or 'string').strip().lower()
    return _PARAM_TYPE_ALIASES.get(text, text or 'string')


def _normalize_param_spec(item: dict):
    if not isinstance(item, dict):
        return None
    name = str(item.get('name') or '').strip()
    if not name:
        return None
    normalized = deepcopy(item)
    normalized['name'] = name
    normalized['type'] = _normalize_param_type(item.get('type'))
    normalized['required'] = bool(item.get('required', False))
    normalized['description'] = str(item.get('description') or '').strip()
    normalized['default'] = item.get('default') if 'default' in item else None
    if 'min' in item:
        normalized['min'] = item.get('min')
    if 'max' in item:
        normalized['max'] = item.get('max')
    if 'options' in item and isinstance(item.get('options'), (list, tuple)):
        normalized['options'] = list(item.get('options'))
    return normalized


def normalize_script_metadata(metadata: dict | None, fallback_name: str = '') -> dict:
    if not isinstance(metadata, dict) or not metadata:
        return {}
    normalized = deepcopy(metadata)
    fallback = str(fallback_name or '').strip()
    name = str(metadata.get('name') or fallback).strip() or fallback
    display_name = str(metadata.get('display_name') or name or fallback).strip() or name or fallback
    description = str(metadata.get('description') or '').strip()
    category = str(metadata.get('category') or '').strip()
    tags = [str(item).strip() for item in (metadata.get('tags') or []) if str(item).strip()]
    platforms = normalize_script_platforms(metadata.get('platforms'))
    params = []
    for item in metadata.get('params') or []:
        normalized_item = _normalize_param_spec(item)
        if normalized_item is not None:
            params.append(normalized_item)
    normalized['name']=name
    normalized['display_name']=display_name
    normalized['description']=description
    normalized['category']=category
    normalized['tags']=tags
    normalized['platforms']=platforms
    normalized['params']=params
    return normalized


def _coerce_boolean(value, param_name: str):
    if isinstance(value, bool):
        return value
    text = str(value or '').strip().lower()
    if text in {'1','true','yes','on'}:
        return True
    if text in {'0','false','no','off'}:
        return False
    raise ValueError(f'Invalid boolean param: {param_name}')


def _coerce_number(value, param_name: str, integer: bool=False):
    try:
        return int(str(value).strip()) if integer else float(str(value).strip())
    except Exception:
        raise ValueError(f'Invalid {"integer" if integer else "number"} param: {param_name}')


def _apply_param_limits(spec: dict, value):
    minimum = spec.get('min')
    maximum = spec.get('max')
    if minimum is not None and value < minimum:
        raise ValueError(f'Param "{spec.get("name", "")}" must be >= {minimum}')
    if maximum is not None and value > maximum:
        raise ValueError(f'Param "{spec.get("name", "")}" must be <= {maximum}')
    return value


def coerce_script_param_value(spec: dict, value):
    param_name = str(spec.get('name') or '').strip() or 'param'
    param_type = _normalize_param_type(spec.get('type'))
    if param_type == 'integer':
        return _apply_param_limits(spec, _coerce_number(value, param_name, integer=True))
    if param_type == 'number':
        return _apply_param_limits(spec, _coerce_number(value, param_name, integer=False))
    if param_type == 'boolean':
        return _coerce_boolean(value, param_name)
    if param_type == 'select':
        allowed = spec.get('options') or []
        text_value = str(value)
        if allowed and text_value not in allowed:
            raise ValueError(f'Invalid option for {param_name}: {text_value}')
        return text_value
    return str(value)


def resolve_script_params(metadata: dict | None, raw_params: dict | None) -> dict:
    normalized_metadata = normalize_script_metadata(metadata or {})
    param_specs = normalized_metadata.get('params') or []
    if not param_specs:
        return dict(raw_params or {}) if isinstance(raw_params, dict) else {}
    raw = dict(raw_params or {}) if isinstance(raw_params, dict) else {}
    resolved = {}
    for spec in param_specs:
        name = spec.get('name') or ''
        has_value = name in raw
        raw_value = raw.get(name)
        if not has_value or raw_value in (None, ''):
            if 'default' in spec and spec.get('default') is not None:
                raw_value = spec.get('default')
                has_value = True
            elif spec.get('required'):
                raise ValueError(f'Missing required script param: {name}')
            else:
                continue
        resolved[name] = coerce_script_param_value(spec, raw_value)
    for key, value in raw.items():
        if key not in resolved:
            resolved[key] = value
    return resolved
