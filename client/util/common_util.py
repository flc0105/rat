
import os



def check_privilege():
    if os.name == 'nt':
        from client.util.win32util import get_integrity_level
        return get_integrity_level()
    elif os.name == 'posix':
        # 1. 检查是否为root权限
        if os.geteuid() == 0:
            # 2. 区分是临时sudo还是真正的root用户
            if 'SUDO_USER' in os.environ:
                return 'Root (via sudo)'
            return 'Root'
        else:
            return 'User'
    else:
        return 'N/A'
