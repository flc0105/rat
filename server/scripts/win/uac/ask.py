import ctypes

from core.utils.client_util import get_executable_path_for_shell

exec, argv = get_executable_path_for_shell()
result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exec, argv, None, 1)

if result > 32:
    print('✓ Elevated to administrator')
else:
    print(f'✗ Elevation failed (error code: {result})')
