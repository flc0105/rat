import os

if os.name == 'nt':
    import win32process
    import win32security
    import ntsecuritycon


def get_integrity():
    """
    获取当前进程权限
    """
    integrity_level = {
        0x0000: 'Untrusted',
        0x1000: 'Low',
        0x2000: 'Medium',
        0x2100: 'Medium high',
        0x3000: 'High',
        0x4000: 'System',
        0x5000: 'Protected process',
    }
    h_token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_READ)
    sid = win32security.GetTokenInformation(h_token, ntsecuritycon.TokenIntegrityLevel)[0]
    return integrity_level.get(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1))
