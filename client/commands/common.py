import contextlib
import inspect
import io
import locale
import os
import subprocess
import sys
import threading
import time

from client.commands.base import CommandBase
from core.utils.client_util.decorator import desc
from core.utils.common_util import format_dict
from core.utils.logger import logger


class CommonCommands(CommandBase):
    """所有平台通用的命令"""

    # ------------------ 通用输出/子进程工具 ------------------ #
    def _get_default_encoding(self):
        """
        获取系统默认编码
        """
        return locale.getdefaultlocale()[1] or 'utf-8'

    def _read_stream_to_result(self, stream):
        """
        持续读取子进程输出流并发送中间结果
        """
        encoding = self._get_default_encoding()
        while True:
            line = stream.readline()
            if not line:
                break
            self._send_interim_result(1, line.decode(encoding, errors='replace').strip('\n'))

    def _run_shell_command(self, command):
        """
        执行一次性 shell 命令
        """
        return subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

    def _start_stream_process(self, command):
        """
        启动带流式输出的子进程
        """
        return subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )

    def _start_stream_reader_threads(self, process):
        """
        为 stdout/stderr 启动流读取线程
        """
        stdout_thread = threading.Thread(target=self._read_stream_to_result, args=(process.stdout,))
        stderr_thread = threading.Thread(target=self._read_stream_to_result, args=(process.stderr,))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        return stdout_thread, stderr_thread

    def _get_exported_command_methods(self):
        """
        获取所有带 help 标记的命令方法
        """
        return {
            name: method
            for name, method in inspect.getmembers(
                self,
                lambda x: inspect.isfunction(x) or inspect.ismethod(x)
            )
            if hasattr(method, 'help')
        }

    # ------------------ 基础命令 ------------------ #
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
            result = self._run_shell_command(command)
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr
        except Exception as e:
            return 0, str(e)

    @desc('execute shell command and read from streams in parallel')
    def read(self, command):
        process = self._start_stream_process(command)
        self._start_stream_reader_threads(process)
        process.wait()
        time.sleep(0.1)
        self._send_final_result(1, "Command completed successfully")

    @desc('download file')
    def download(self, filename):
        if os.path.isfile(filename):
            self.socket.send_result(self.command_id, 1, 'Preparing to send file', eof=0)
            self.socket.send_result(
                self.command_id,
                1,
                'File length is {}'.format(os.path.getsize(filename)),
                eof=0
            )
            self.socket.send_file(self.command_id, filename)
        else:
            return 0, 'File does not exist'

    @desc('execute python code')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(code, kwargs)
        return 1, output.getvalue()

    @desc('show this help')
    def help(self):
        methods = self._get_exported_command_methods()
        return 1, format_dict({name: method.help for name, method in methods.items()})

    # ------------------ 压缩文件 ------------------ #
    def _validate_directory_exists(self, dir_name):
        """
        校验目录是否存在，并返回绝对路径
        """
        dir_path = os.path.abspath(dir_name)
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f'Directory does not exist: {dir_path}')
        return dir_path

    def _validate_file_exists(self, file_name):
        """
        校验文件是否存在，并返回绝对路径
        """
        file_path = os.path.abspath(file_name)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f'File does not exist: {file_path}')
        return file_path

    @desc('create a zip archive')
    def zip(self, dir_name):
        import pathlib
        import shutil
        import tempfile

        try:
            tempdir = tempfile.mkdtemp()
            dir_path = self._validate_directory_exists(dir_name)
            zip_name = os.path.basename(dir_path)
            parent_dir = pathlib.Path(dir_path).resolve().parent
            filename = shutil.make_archive(
                os.path.join(tempdir, zip_name),
                format='zip',
                root_dir=parent_dir,
                base_dir=os.path.basename(dir_path)
            )
            return 1, f'Archive created: {filename}'
        except Exception as e:
            return 0, str(e)

    @desc('extract files from a zip archive')
    def unzip(self, zip_name):
        import shutil

        try:
            zip_path = self._validate_file_exists(zip_name)
            shutil.unpack_archive(zip_path, os.getcwd())
            return 1, f'Archive extracted to {os.getcwd()}'
        except Exception as e:
            return 0, str(e)

    # ------------------ 连接控制 ------------------ #
    @desc('close connection')
    def kill(self):
        self.socket.close()
        sys.exit(0)

    def _build_reset_command(self):
        """
        构造当前程序重启命令
        """
        if os.name == 'nt':
            from core.utils.client_util.win32util import get_executable_path
            return get_executable_path()

        if os.name == 'posix':
            executable = os.path.realpath(sys.executable)
            argv = os.path.realpath(''.join(sys.argv))
            return f'{executable} {argv}'

        raise RuntimeError(f'Unsupported platform: {os.name}')

    @desc('reset connection')
    def reset(self):
        exec_path = self._build_reset_command()
        if os.name == 'nt':
            subprocess.Popen(exec_path)
        elif os.name == 'posix':
            subprocess.Popen(exec_path, shell=True)
        self.socket.close()
        sys.exit(0)


# import contextlib
# import glob
# import inspect
# import io
# import locale
# import os
# import socket
# import subprocess
# import sys
# import threading
# import time
#
# from client.config.config import SERVER_ADDR, JOB_PATH
# from client.commands.base import CommandBase
# from core.utils.client_util.decorator import desc
# from core.utils.common_util import format_dict, validate_required_args
# from core.utils.logger import logger
#
#
# class CommonCommands(CommandBase):
#     """所有平台通用的命令"""
#
#     def read_stream(self, stream):
#         while True:
#             # 从输入流读取一行数据
#             line = stream.readline()
#             # 如果没有更多数据可读取，则跳出循环
#             if not line:
#                 break
#             # 将读取的字节转换为字符串，并去除行尾的换行符
#             self._send_interim_result(1, line.decode(locale.getdefaultlocale()[1]).strip('\n'))
#
#     @desc('change directory')
#     def cd(self, path):
#         """跨平台的目录切换命令"""
#         try:
#             os.chdir(path)
#             return 1, ""
#         except Exception as e:
#             return 0, str(e)
#
#     @desc('execute shell command')
#     def shell(self, command):
#         """跨平台的shell命令执行"""
#         try:
#             result = subprocess.run(
#                 command,
#                 shell=True,
#                 stdout=subprocess.PIPE,
#                 stderr=subprocess.PIPE,
#                 text=True,
#                 encoding='utf-8',
#                 errors='replace'
#             )
#             if result.returncode == 0:
#                 return 1, result.stdout
#             else:
#                 return 0, result.stderr
#         except Exception as e:
#             return 0, str(e)
#
#     @desc('execute shell command and read from streams in parallel')
#     def read(self, command):
#         cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
#                                stdin=subprocess.DEVNULL)
#         stdout_thread = threading.Thread(target=self.read_stream, args=(cmd.stdout,))
#         stderr_thread = threading.Thread(target=self.read_stream, args=(cmd.stderr,))
#         stdout_thread.daemon = True
#         stderr_thread.daemon = True
#         stdout_thread.start()
#         stderr_thread.start()
#         # 等待命令完成
#         cmd.wait()
#         time.sleep(0.1)
#         self._send_final_result(1, "Command completed successfully")
#
#     @desc('download file')
#     def download(self, filename):
#         if os.path.isfile(filename):
#             self.socket.send_result(self.command_id, 1, 'Preparing to send file', eof=0)
#             self.socket.send_result(self.command_id, 1, 'File length is {}'.format(os.path.getsize(filename)), eof=0)
#             self.socket.send_file(self.command_id, filename)
#         else:
#             return 0, 'File does not exist'
#
#     @desc('execute python code')
#     def pyexec(self, code, kwargs=None):
#         if kwargs is None:
#             kwargs = {}
#         f = io.StringIO()
#         with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
#             exec(code, kwargs)
#         return 1, f.getvalue()
#
#     @desc('show this help')
#     def help(self):
#         methods = {name: method for name, method in
#                    inspect.getmembers(self, lambda x: inspect.isfunction(x) or inspect.ismethod(x))
#                    if hasattr(method, 'help')}
#         return 1, format_dict({name: method.help for name, method in methods.items()})
#
#     @desc('create a zip archive')
#     def zip(self, dir_name):
#         import pathlib
#         import shutil
#         import tempfile
#         tempdir = tempfile.mkdtemp()
#         dir_name = os.path.abspath(dir_name)
#         if not os.path.isdir(dir_name):
#             return 0, f'Directory does not exist: {dir_name}'
#         zip_name = os.path.basename(dir_name)
#         pardir = pathlib.Path(dir_name).resolve().parent
#         filename = shutil.make_archive(os.path.join(tempdir, zip_name), format='zip', root_dir=pardir,
#                                        base_dir=os.path.basename(dir_name))
#         return 1, f'Archive created: {filename}'
#
#     @desc('extract files from a zip archive')
#     def unzip(self, zip_name):
#         import shutil
#         zip_name = os.path.abspath(zip_name)
#         if not os.path.isfile(zip_name):
#             return 0, f'File does not exist: {zip_name}'
#         shutil.unpack_archive(zip_name, os.getcwd())
#         return 1, f'Archive extracted to {os.getcwd()}'
#
#     @desc('close connection')
#     def kill(self):
#         self.socket.close()
#         sys.exit(0)
#
#     @desc('reset connection')
#     def reset(self):
#         if os.name == 'nt':
#             from core.utils.client_util.win32util import get_executable_path
#             exec_path = get_executable_path()
#             subprocess.Popen(exec_path)
#         elif os.name == 'posix':
#             executable = os.path.realpath(sys.executable)
#             argv = os.path.realpath(''.join(sys.argv))
#             exec_path = f'{executable} {argv}'
#             subprocess.Popen(exec_path, shell=True)
#         self.socket.close()
#         sys.exit(0)