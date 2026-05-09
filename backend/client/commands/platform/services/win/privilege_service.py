class WinPrivilegeService:
    """
    Windows 提权/管理员执行能力。
    """

    def __init__(self, owner):
        self.owner = owner

    def run_as_admin(self, command):
        import ctypes
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                'runas',
                'cmd.exe',
                f'/c {command}',
                None,
                1,
            )
            if result > 32:
                return 1, f'Executed: {command}'
            return 0, f'Failed with code: {result}'
        except Exception as e:
            return 0, f'Failed: {e}'