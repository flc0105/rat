import os


def check_privilege():
    if os.name == 'posix':
        if os.geteuid() == 0:
            if 'SUDO_USER' in os.environ:
                return 'Root (via sudo)'
            return 'Root'
        return 'User'
    if os.name == 'nt':
        from client.commands.platform.utils.win_util import get_integrity_level
        return get_integrity_level()

    return 'N/A'
