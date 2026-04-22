import platform
import sys
from dataclasses import dataclass
from enum import Enum


class PlatformAlias(str, Enum):
    WIN = 'win'
    IOS = 'ios'
    MAC = 'mac'
    LINUX = 'linux'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class PlatformInfo:
    alias: str
    display_name: str
    system_name: str


_PLATFORM_INFO_MAP = {
    'Windows': PlatformInfo(alias=PlatformAlias.WIN.value, display_name='Windows', system_name='Windows'),
    'Linux': PlatformInfo(alias=PlatformAlias.LINUX.value, display_name='Linux', system_name='Linux'),
}


# add 平台信息统一入口 2026-04-21
def detect_platform_info() -> PlatformInfo:
    system_name = platform.system()

    if system_name == 'Darwin':
        if sys.platform == 'ios':
            return PlatformInfo(alias=PlatformAlias.IOS.value, display_name='iOS', system_name=system_name)
        return PlatformInfo(alias=PlatformAlias.MAC.value, display_name='macOS', system_name=system_name)

    if system_name in _PLATFORM_INFO_MAP:
        return _PLATFORM_INFO_MAP[system_name]

    normalized_system_name = system_name or 'Unknown'
    return PlatformInfo(
        alias=PlatformAlias.UNKNOWN.value,
        display_name=normalized_system_name,
        system_name=normalized_system_name,
    )


# add 平台比较统一使用 alias 2026-04-21
def detect_platform_alias() -> str:
    return detect_platform_info().alias


def detect_platform_name() -> str:
    return detect_platform_info().display_name
