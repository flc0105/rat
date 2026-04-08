import ctypes

from core.utils.client_util import get_exec_and_args

exec, argv = get_exec_and_args()

result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exec, argv, None, 1)

if result > 32:
    print('✓ Elevated to administrator')
else:
    print(f'✗ Elevation failed (error code: {result})')
