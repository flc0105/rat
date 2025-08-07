# prompts for credentials, validates them, and loops until correct ones are entered
import locale
import subprocess

from client.util.win32util import logon_user

command = r'$cred=$Host.UI.PromptForCredential($null,$null,$env:username,$null);' \
          'if($cred) {echo $cred.GetNetworkCredential().UserName $cred.GetNetworkCredential().Password} ' \
          'else {echo `n} '

while True:
    p = subprocess.Popen(f'powershell.exe {command}', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True)
    stdout, stderr = p.communicate()
    if stderr:
        raise Exception(stderr.decode(locale.getdefaultlocale()[1]))
    lines = stdout.decode(locale.getdefaultlocale()[1]).splitlines()
    if logon_user(*lines):
        print(str(lines))
        break
    else:
        print(f'Wrong try: {str(lines)}')
