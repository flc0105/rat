import ntsecuritycon
import win32process
import win32security


def get_integrity_level() -> str:
    """
    获取当前进程的完整性级别
    """
    mapping = {
        0x0000: 'Untrusted',
        0x1000: 'Low',
        0x2000: 'Medium',
        0x2100: 'Medium High',
        0x3000: 'High',
        0x4000: 'System',
        0x5000: 'Protected',
    }

    try:
        h_token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_READ
        )
        sid = win32security.GetTokenInformation(h_token, ntsecuritycon.TokenIntegrityLevel)[0]
        return mapping.get(sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1), 'Unknown')
    except Exception:
        return 'Unknown'