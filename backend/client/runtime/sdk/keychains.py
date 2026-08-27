"""
Script SDK keychains 入口。

这里直接复用 client.runtime.keychains 的原有逻辑，不另开一套凭证读取实现。
"""

from client.runtime.keychains import (  # noqa: F401
    KEYCHAINS_CREATE_GRANT,
    KEYCHAINS_LIST_GRANT,
    KEYCHAINS_RESOLVE_GRANT,
    KeychainError,
    LoginCredential,
    MACHINE_SCOPE,
    SHARED_MACHINE_ID,
    SHARED_SCOPE,
    SecretCredential,
    SecretValue,
    create_login,
    create_secret,
    get_keychain,
    get_login,
    get_secret,
    list,
    list_keychains,
)

__all__ = [
    'KEYCHAINS_CREATE_GRANT',
    'KEYCHAINS_LIST_GRANT',
    'KEYCHAINS_RESOLVE_GRANT',
    'KeychainError',
    'LoginCredential',
    'MACHINE_SCOPE',
    'SHARED_MACHINE_ID',
    'SHARED_SCOPE',
    'SecretCredential',
    'SecretValue',
    'create_login',
    'create_secret',
    'get_keychain',
    'get_login',
    'get_secret',
    'list',
    'list_keychains',
]
