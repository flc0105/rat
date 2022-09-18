import locale
import os
import subprocess


class Command:

    @staticmethod
    def cd(path):
        """
        切换目录
        """
        if not path:
            return 1, ''
        if os.path.isdir(path):
            os.chdir(path)
            return 1, ''
        else:
            return 0, 'Cannot find the path specified'

    @staticmethod
    def shell(command):
        """
        执行shell命令
        """
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
        stdout = str(cmd.stdout.read(), locale.getdefaultlocale()[1])
        stderr = str(cmd.stderr.read(), locale.getdefaultlocale()[1])
        if stdout:
            return 1, stdout
        elif stderr:
            return 0, stderr
        else:
            return 1, ''

    @staticmethod
    def download(server, filename):
        """
        给服务端发送文件
        """
        if os.path.isfile(filename):
            server.send_file(filename)
        else:
            server.send_result(0, 'File does not exist')
