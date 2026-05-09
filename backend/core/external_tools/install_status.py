from typing import Any


INSTALL_STATUS_INSTALLED = 'installed'
INSTALL_STATUS_NOT_INSTALLED = 'not_installed'
INSTALL_STATUS_PARTIAL = 'partial'
INSTALL_STATUS_ERROR = 'error'
INSTALL_STATUS_UNKNOWN = 'unknown'
KNOWN_INSTALL_STATUSES = {
    INSTALL_STATUS_INSTALLED,
    INSTALL_STATUS_NOT_INSTALLED,
    INSTALL_STATUS_PARTIAL,
    INSTALL_STATUS_ERROR,
    INSTALL_STATUS_UNKNOWN,
}


def normalize_install_status(value: Any) -> str:
    if isinstance(value, str):
        status = value.strip().lower()
        return status if status in KNOWN_INSTALL_STATUSES else INSTALL_STATUS_UNKNOWN

    item = value if isinstance(value, dict) else {}
    if item.get('error'):
        return INSTALL_STATUS_ERROR

    explicit = str(item.get('install_status') or '').strip().lower()
    if explicit in KNOWN_INSTALL_STATUSES:
        return explicit

    installed = item.get('installed')
    if installed is True:
        return INSTALL_STATUS_INSTALLED
    if installed is False:
        return INSTALL_STATUS_NOT_INSTALLED

    missing_execs = item.get('missing_execs')
    if isinstance(missing_execs, dict) and missing_execs:
        return INSTALL_STATUS_PARTIAL

    return INSTALL_STATUS_UNKNOWN


def is_installed_status(value: Any) -> bool:
    return normalize_install_status(value) == INSTALL_STATUS_INSTALLED
