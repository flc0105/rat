"""
Script SDK keychains 入口。

这里直接复用 client.runtime.keychains 的原有逻辑，不另开一套凭证读取实现。
"""

from client.runtime.keychains import (  # noqa: F401
    KeychainError,
    LoginCredential,
    MACHINE_SCOPE,
    SERVER_MACHINE_ID,
    SERVER_SCOPE,
    SecretCredential,
    SecretValue,
    get_keychain,
    get_login,
    get_secret,
)

__all__ = [
    'KeychainError',
    'LoginCredential',
    'MACHINE_SCOPE',
    'SERVER_MACHINE_ID',
    'SERVER_SCOPE',
    'SecretCredential',
    'SecretValue',
    'get_keychain',
    'get_login',
    'get_secret',
]
