SCRIPT_METADATA = {
    "name": "win/uac/ask",
    "display_name": "Elevate to Administrator",
    "description": "Launch a new client session with administrator privileges via UAC prompt",
    "platforms": ["windows"],
    "category": "uac",
    "params": []
}

import ctypes
from core.utils.client_util import get_exec_and_args

exec, argv = get_exec_and_args()

result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exec, argv, None, 1)

if result > 32:
    print('✓ Elevated to administrator')
else:
    print(f'✗ Elevation failed (error code: {result})')