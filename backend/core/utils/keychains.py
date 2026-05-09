"""
Client-side helper for reading server-side Keychains from scripts.

Usage:
    from core.utils.keychains import get_secret, get_login

    token = get_secret("github-token").getvalue()

    login = get_login("nas-admin")
    username = login.username
    password = login.password.getvalue()

说明：
- 这个工具只读取服务端 runtime/keychains 里的凭证。
- 第一版使用 allow_anonymous 的 resolve 接口，适合个人运维环境。
- SecretValue 默认打印为掩码，必须显式 .getvalue() 才返回真实值。
"""

from dataclasses import dataclass
from typing import Any


SERVER_SCOPE = 'server'
MACHINE_SCOPE = 'machine'
SERVER_MACHINE_ID = '__server__'


class KeychainError(RuntimeError):
    """Keychains helper 统一异常。"""
    pass


class SecretValue:
    """
    包装敏感值。

    避免 print()/repr() 时直接把明文打到日志里；
    脚本确实要使用明文时，显式调用 getvalue()。
    """

    def __init__(self, value: Any = ''):
        self._value = '' if value is None else str(value)

    def getvalue(self) -> str:
        return self._value

    def is_empty(self) -> bool:
        return self._value == ''

    def __bool__(self) -> bool:
        return bool(self._value)

    def __str__(self) -> str:
        return '********' if self._value else ''

    def __repr__(self) -> str:
        return 'SecretValue(********)' if self._value else 'SecretValue()'


@dataclass(frozen=True)
class LoginCredential:
    name: str
    username: str
    password: SecretValue
    site: str = ''
    note: str = ''
    machine_id: str = ''
    hostname: str = ''
    created_at: str = ''
    updated_at: str = ''


@dataclass(frozen=True)
class SecretCredential:
    name: str
    value: SecretValue
    note: str = ''
    machine_id: str = ''
    hostname: str = ''
    created_at: str = ''
    updated_at: str = ''


def _safe_text(value: Any) -> str:
    return '' if value is None else str(value).strip()


def _normalize_scope(scope: str) -> str:
    value = _safe_text(scope).lower()
    if value in ('server', '__server__'):
        return SERVER_SCOPE
    return MACHINE_SCOPE


def _get_current_machine_id() -> str:
    try:
        from core.device.machine_identity import build_machine_identity_payload

        payload = build_machine_identity_payload()
        return _safe_text(payload.get('machine_id_hash'))
    except Exception as exc:
        raise KeychainError(f'Failed to detect current machine id: {exc}') from exc


def _resolve_machine_id(scope: str, machine_id: str = '') -> str:
    normalized_scope = _normalize_scope(scope)
    if normalized_scope == SERVER_SCOPE:
        return SERVER_MACHINE_ID

    explicit_machine_id = _safe_text(machine_id)
    if explicit_machine_id:
        return explicit_machine_id

    current_machine_id = _get_current_machine_id()
    if not current_machine_id:
        raise KeychainError('Current machine id is empty')
    return current_machine_id


def _request_keychain_item(name: str, *, kind: str = '', scope: str = MACHINE_SCOPE, machine_id: str = '') -> dict:
    normalized_name = _safe_text(name)
    if not normalized_name:
        raise ValueError('keychain name is required')

    normalized_kind = _safe_text(kind).lower()
    if normalized_kind and normalized_kind not in ('login', 'secret'):
        raise ValueError('kind must be login or secret')

    payload = {
        'name': normalized_name,
        'kind': normalized_kind,
        'scope': _normalize_scope(scope),
        'machine_id': _resolve_machine_id(scope, machine_id),
    }

    try:
        from client.http.client_api import ClientApiClient

        data = ClientApiClient().post_data('/api/keychains/resolve', json=payload, timeout=15)
    except ImportError as exc:
        raise KeychainError('client.http.client_api is required to resolve keychains') from exc
    except Exception as exc:
        # ClientApiError 也统一包装，调用方只需要捕获 KeychainError。
        raise KeychainError(str(exc) or 'Failed to resolve keychain') from exc

    if not isinstance(data, dict):
        raise KeychainError('Invalid keychain resolve response')

    item = data.get('item')
    if not isinstance(item, dict):
        raise KeychainError('Keychain item missing in response')

    return item


def _build_login_credential(item: dict) -> LoginCredential:
    if _safe_text(item.get('kind')).lower() != 'login':
        raise KeychainError(f'Keychain is not a login: {item.get("name") or ""}')

    return LoginCredential(
        name=_safe_text(item.get('name')),
        username=_safe_text(item.get('username')),
        password=SecretValue(item.get('secret_value')),
        site=_safe_text(item.get('site')),
        note=_safe_text(item.get('note')),
        machine_id=_safe_text(item.get('machine_id')),
        hostname=_safe_text(item.get('hostname')),
        created_at=_safe_text(item.get('created_at')),
        updated_at=_safe_text(item.get('updated_at')),
    )


def _build_secret_credential(item: dict) -> SecretCredential:
    if _safe_text(item.get('kind')).lower() != 'secret':
        raise KeychainError(f'Keychain is not a secret: {item.get("name") or ""}')

    return SecretCredential(
        name=_safe_text(item.get('name')),
        value=SecretValue(item.get('secret_value')),
        note=_safe_text(item.get('note')),
        machine_id=_safe_text(item.get('machine_id')),
        hostname=_safe_text(item.get('hostname')),
        created_at=_safe_text(item.get('created_at')),
        updated_at=_safe_text(item.get('updated_at')),
    )


def get_secret(name: str, *, scope: str = MACHINE_SCOPE, machine_id: str = '') -> SecretValue:
    """
    读取 Secrets 类型凭证的 value。

    默认读取当前 machine_id 下的凭证；读取服务端凭证时使用：
        get_secret('xxx', scope='server')
    """
    item = _request_keychain_item(name, kind='secret', scope=scope, machine_id=machine_id)
    return SecretValue(item.get('secret_value'))


def get_login(name: str, *, scope: str = MACHINE_SCOPE, machine_id: str = '') -> LoginCredential:
    """
    读取 Logins 类型凭证。

    返回对象字段：
        login.username
        login.password.getvalue()
    """
    item = _request_keychain_item(name, kind='login', scope=scope, machine_id=machine_id)
    return _build_login_credential(item)


def get_keychain(name: str, *, kind: str = '', scope: str = MACHINE_SCOPE, machine_id: str = ''):
    """
    通用读取入口。

    kind 为空时由服务端按 name 查找；返回 LoginCredential 或 SecretCredential。
    """
    item = _request_keychain_item(name, kind=kind, scope=scope, machine_id=machine_id)
    item_kind = _safe_text(item.get('kind')).lower()
    if item_kind == 'login':
        return _build_login_credential(item)
    if item_kind == 'secret':
        return _build_secret_credential(item)
    raise KeychainError(f'Unsupported keychain kind: {item_kind or "unknown"}')
