from typing import Any


def normalize_platform(value: Any) -> str:
    text = str(value or '').strip().lower()
    aliases = {
        'windows': 'win',
        'win32': 'win',
        'darwin': 'mac',
        'macos': 'mac',
        'osx': 'mac',
        'linux': 'linux',
        'ios': 'ios',
        'common': '*',
        'all': '*',
        '*': '*',
    }
    return aliases.get(text, text)


def normalize_arch(value: Any) -> str:
    text = str(value or '').strip().lower().replace('-', '_')
    aliases = {
        'x86_64': 'amd64',
        'amd64': 'amd64',
        'i386': '386',
        'i686': '386',
        'aarch64': 'arm64',
        'arm64': 'arm64',
    }
    return aliases.get(text, text)


def platform_key(platform_alias: Any, arch: Any) -> str:
    platform_value = normalize_platform(platform_alias)
    arch_value = normalize_arch(arch)
    if not platform_value or not arch_value:
        return ''
    return f'{platform_value}-{arch_value}'
