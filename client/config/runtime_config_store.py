import json
import os
import sys
import tempfile


CONFIG_ENV_NAME = 'RATCLIENT_RUNTIME_CONFIG_PATH'
CONFIG_FILE_NAME = 'runtime_config.json'
APP_DIR_NAME = 'ratclient'


def get_runtime_config_path() -> str:
    """
    返回 runtime 配置覆盖文件路径。

    注意：
    - 这里永远不返回 client/config/runtime_config.py
    - 打包后也只写外部可写目录
    - 可用 RATCLIENT_RUNTIME_CONFIG_PATH 显式覆盖
    """
    override_path = os.environ.get(CONFIG_ENV_NAME, '').strip()
    if override_path:
        return os.path.abspath(os.path.expanduser(override_path))

    return os.path.join(get_runtime_config_dir(), CONFIG_FILE_NAME)


def get_runtime_config_dir() -> str:
    if os.name == 'nt':
        base_dir = os.environ.get('APPDATA', '').strip()
        if not base_dir:
            base_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
        return os.path.join(base_dir, APP_DIR_NAME)

    if sys.platform == 'darwin':
        return os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', APP_DIR_NAME)

    if sys.platform == 'ios':
        return os.path.join(os.path.expanduser('~/Documents'), f'.{APP_DIR_NAME}')

    base_dir = os.environ.get('XDG_CONFIG_HOME', '').strip()
    if not base_dir:
        base_dir = os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base_dir, APP_DIR_NAME)


def load_runtime_overrides() -> dict:
    path = get_runtime_config_path()
    if not os.path.isfile(path):
        return {}

    try:
        with open(path, 'r', encoding='utf-8') as file_obj:
            data = json.load(file_obj)
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    result = {}
    for key, value in data.items():
        if isinstance(key, str) and key.isupper():
            result[key] = value
    return result


def save_runtime_overrides(overrides: dict):
    if not isinstance(overrides, dict):
        raise TypeError('runtime overrides must be a dict')

    path = get_runtime_config_path()
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    os.makedirs(directory, exist_ok=True)

    normalized = {}
    for key, value in overrides.items():
        if isinstance(key, str) and key.isupper():
            normalized[key] = value

    fd, temp_path = tempfile.mkstemp(prefix='.runtime_config_', suffix='.json.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file_obj:
            json.dump(normalized, file_obj, ensure_ascii=False, indent=2, sort_keys=True)
            file_obj.write('\n')
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        raise

    return path


def update_runtime_override(key: str, value):
    normalized_key = str(key or '').strip().upper()
    if not normalized_key:
        raise ValueError('runtime config key is required')
    if not normalized_key.isupper():
        raise ValueError(f'invalid runtime config key: {key}')

    overrides = load_runtime_overrides()
    overrides[normalized_key] = value
    return save_runtime_overrides(overrides)