import ast
import sys
from dataclasses import dataclass

from client.config import runtime_config
from client.config.runtime_config_store import get_runtime_config_path, update_runtime_override


@dataclass
class RuntimeConfigUpdateResult:
    key: str
    old_value: object
    new_value: object
    store_path: str


class RuntimeConfigService:
    """
    client runtime_config 管理服务。

    职责：
    - 读取 client.config.runtime_config 当前配置项
    - set 后实时更新当前进程 runtime_config 模块值
    - 持久化写入外部 runtime_config.json
    - 不读取、不修改 ratclient.py
    - 不读取、不修改 client/config/runtime_config.py 源码文件
    """

    SUPPORTED_TYPES = (str, int, float, bool, type(None))
    BOOL_TRUE_VALUES = {'true', '1', 'yes', 'y', 'on'}
    BOOL_FALSE_VALUES = {'false', '0', 'no', 'n', 'off'}

    def list_config_items(self) -> list[tuple[str, object]]:
        return [
            (key, getattr(runtime_config, key))
            for key in sorted(self._iter_runtime_config_keys())
        ]

    def format_config_items(self) -> str:
        items = self.list_config_items()
        if not items:
            return 'No runtime config items'
        return '\n'.join(
            f'{key} = {self.format_value(value)}'
            for key, value in items
        )

    def set_config_value(self, key: str, raw_value: str) -> RuntimeConfigUpdateResult:
        normalized_key = self.normalize_key(key)
        if not normalized_key:
            raise ValueError('Config key is required')
        if not self.is_supported_key(normalized_key):
            raise KeyError(f'Unknown or unsupported runtime config key: {normalized_key}')

        old_value = getattr(runtime_config, normalized_key)
        new_value = self.coerce_value(raw_value, old_value)

        store_path = update_runtime_override(normalized_key, new_value)
        setattr(runtime_config, normalized_key, new_value)
        self._sync_loaded_runtime_symbols(normalized_key, old_value, new_value)

        return RuntimeConfigUpdateResult(
            key=normalized_key,
            old_value=old_value,
            new_value=new_value,
            store_path=store_path,
        )

    def get_store_path(self) -> str:
        return get_runtime_config_path()

    def normalize_key(self, key: str) -> str:
        return str(key or '').strip().upper()

    def is_supported_key(self, key: str) -> bool:
        if not isinstance(key, str) or not key.isupper():
            return False
        if not hasattr(runtime_config, key):
            return False
        value = getattr(runtime_config, key)
        return isinstance(value, self.SUPPORTED_TYPES)

    def format_value(self, value) -> str:
        if isinstance(value, str):
            return repr(value)
        if isinstance(value, bool):
            return 'True' if value else 'False'
        if value is None:
            return 'None'
        return str(value)

    def coerce_value(self, raw_value: str, current_value):
        text = str(raw_value or '').strip()
        if text == '':
            raise ValueError('Config value is required')

        if isinstance(current_value, bool):
            return self._coerce_bool(text)

        if isinstance(current_value, int) and not isinstance(current_value, bool):
            return self._coerce_int(text)

        if isinstance(current_value, float):
            return self._coerce_float(text)

        if current_value is None:
            return self._coerce_untyped(text)

        if isinstance(current_value, str):
            return self._coerce_string(text)

        raise TypeError(f'Unsupported config value type: {type(current_value).__name__}')

    def _coerce_bool(self, text: str) -> bool:
        lowered = text.strip().lower()
        if lowered in self.BOOL_TRUE_VALUES:
            return True
        if lowered in self.BOOL_FALSE_VALUES:
            return False
        raise ValueError(f'Invalid boolean value: {text}')

    def _coerce_int(self, text: str) -> int:
        try:
            return int(text, 10)
        except Exception as e:
            raise ValueError(f'Invalid integer value: {text}') from e

    def _coerce_float(self, text: str) -> float:
        try:
            return float(text)
        except Exception as e:
            raise ValueError(f'Invalid float value: {text}') from e

    def _coerce_string(self, text: str) -> str:
        try:
            value = ast.literal_eval(text)
            if isinstance(value, str):
                return value
        except Exception:
            pass
        return text

    def _coerce_untyped(self, text: str):
        lowered = text.lower()
        if lowered in ('none', 'null'):
            return None
        if lowered in self.BOOL_TRUE_VALUES:
            return True
        if lowered in self.BOOL_FALSE_VALUES:
            return False
        try:
            return int(text, 10)
        except Exception:
            pass
        try:
            return float(text)
        except Exception:
            pass
        return self._coerce_string(text)

    def _iter_runtime_config_keys(self):
        for key, value in vars(runtime_config).items():
            if key.isupper() and isinstance(value, self.SUPPORTED_TYPES):
                yield key

    def _sync_loaded_runtime_symbols(self, key: str, old_value, new_value):
        """
        兼容当前代码中已有的 from client.config.runtime_config import KEY 写法。

        这里只改当前进程内已经加载的 client/core/ratclient 模块同名常量，
        不读写任何源码文件。
        """
        for module_name, module in list(sys.modules.items()):
            if module is None:
                continue
            if not self._should_touch_loaded_module(module_name):
                continue

            self._set_attr_if_equal(module, key, old_value, new_value)
            module_dict = getattr(module, '__dict__', {}) or {}
            for value in list(module_dict.values()):
                if isinstance(value, type):
                    self._set_attr_if_equal(value, key, old_value, new_value)

    def _should_touch_loaded_module(self, module_name: str) -> bool:
        return (
            module_name == 'ratclient'
            or module_name.startswith('client.')
            or module_name.startswith('core.')
        )

    def _set_attr_if_equal(self, target, key: str, old_value, new_value):
        if not hasattr(target, key):
            return
        try:
            current_value = getattr(target, key)
            if current_value != old_value:
                return
            setattr(target, key, new_value)
        except Exception:
            pass