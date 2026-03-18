import base64
import contextlib
import inspect
import io
import json
import locale
import os
import shutil
import subprocess
import sys
import threading
import time

from client.commands.base import CommandBase
from core.utils.decorator import desc
from core.utils.formatting import format_dict
import stat as stat_module


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
        encoding = self._get_default_encoding()
        return subprocess.run(
            command,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=encoding,
            errors='replace',
            timeout=30
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

    def _resolve_target_path(self, path: str) -> str:
        """
        将传入路径解析为当前客户端上的绝对路径
        - 空路径默认当前工作目录
        - 相对路径基于当前 cwd
        """
        raw_path = (path or '').strip()
        if not raw_path:
            raw_path = '.'

        if os.path.isabs(raw_path):
            return os.path.abspath(raw_path)

        return os.path.abspath(os.path.join(os.getcwd(), raw_path))

    def _build_parent_path(self, path: str):
        """
        获取上级目录；如果已经到根目录，则返回 None
        """
        current = os.path.abspath(path)
        parent = os.path.dirname(current)
        if parent == current:
            return None
        return parent

    def _build_directory_entry(self, entry):
        """
        构造目录项描述
        """
        stat_result = entry.stat(follow_symlinks=False)
        is_dir = entry.is_dir(follow_symlinks=True)
        is_symlink = entry.is_symlink()
        is_hidden = self._is_hidden_entry(entry, stat_result)

        return {
            'name': entry.name,
            'path': os.path.abspath(entry.path),
            'is_dir': is_dir,
            'is_symlink': is_symlink,
            'is_hidden': is_hidden,
            'size': 0 if is_dir else stat_result.st_size,
            'modified_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_result.st_mtime))
        }

    def _is_hidden_entry(self, entry, stat_result):
        """
        判断目录项是否为隐藏文件
        - Unix/macOS: 以 . 开头
        - Windows: 支持文件属性隐藏位
        """
        if entry.name.startswith('.'):
            return True

        if os.name == 'nt':
            file_attrs = getattr(stat_result, 'st_file_attributes', 0)
            if file_attrs & getattr(stat_module, 'FILE_ATTRIBUTE_HIDDEN', 0):
                return True

        return False

    def _strip_wrapped_quotes(self, value: str) -> str:
        """
        去掉参数最外层成对引号
        """
        text = (value or '').strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            return text[1:-1]
        return text

    def _decode_structured_arg(self, raw):
        """
        解码结构化参数：
        - __json__:<base64(json)>
        - 普通字符串
        """
        text = self._strip_wrapped_quotes(raw)
        if not text:
            return ''

        prefix = '__json__:'
        if text.startswith(prefix):
            encoded = text[len(prefix):]
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode('utf-8')
            return json.loads(decoded)

        return text

    def _extract_path_arg(self, raw) -> str:
        """
        提取路径参数，兼容普通字符串和结构化参数
        """
        value = self._decode_structured_arg(raw)
        if isinstance(value, dict):
            return (value.get('path') or '').strip()
        return (value or '').strip()

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
        except subprocess.TimeoutExpired:
            return 0, 'Command timed out'
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

    @desc('Download a file by path')
    def download_path(self, path=''):
        """
        按路径下载文件，供 Web 远程文件浏览使用。
        """
        try:
            file_path = self._resolve_target_path(self._extract_path_arg(path))
            if not os.path.exists(file_path):
                return 0, f'Path not found: {file_path}'
            if not os.path.isfile(file_path):
                return 0, f'Not a file: {file_path}'

            file_size = os.path.getsize(file_path)
            self.socket.send_result(self.command_id, 1, 'Preparing file transfer...', eof=0)
            self.socket.send_result(self.command_id, 1, f'File size: {file_size} bytes', eof=0)
            self.socket.send_file(self.command_id, file_path)
        except Exception as e:
            return 0, f'Failed to download file: {e}'

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

    @desc('Browse directory as JSON payload')
    def browse_dir(self, path=''):
        """
        浏览目录，返回 JSON 结构，供 Web 端可视化文件浏览使用。
        """
        try:
            directory = self._resolve_target_path(self._extract_path_arg(path))

            if not os.path.exists(directory):
                return 0, f'Directory not found: {directory}'

            if not os.path.isdir(directory):
                return 0, f'Not a directory: {directory}'

            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    try:
                        entries.append(self._build_directory_entry(entry))
                    except Exception:
                        # 某些文件可能无权限读取 stat，跳过即可，避免整个目录浏览失败
                        continue

            entries.sort(key=lambda item: (not item['is_dir'], item['name'].lower()))

            payload = {
                'current_path': directory,
                'parent_path': self._build_parent_path(directory),
                'entries': entries
            }
            return 1, json.dumps(payload, ensure_ascii=False)
        except Exception as e:
            return 0, f'Failed to browse directory: {e}'

    @desc('Delete a file or directory')
    def delete_path(self, path=''):
        """
        删除文件或目录。
        """
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))

            if not os.path.exists(target_path):
                return 0, f'Path not found: {target_path}'

            if os.path.isdir(target_path):
                shutil.rmtree(target_path)
                return 1, f'Directory deleted: {target_path}'

            os.remove(target_path)
            return 1, f'File deleted: {target_path}'
        except Exception as e:
            return 0, f'Failed to delete path: {e}'

    @desc('Create a directory')
    def mkdir_path(self, path=''):
        """
        创建目录。
        """
        try:
            target_path = self._resolve_target_path(self._extract_path_arg(path))
            if not target_path:
                return 0, 'Path is required'

            if os.path.exists(target_path):
                return 0, f'Path already exists: {target_path}'

            os.makedirs(target_path, exist_ok=False)
            return 1, f'Directory created: {target_path}'
        except Exception as e:
            return 0, f'Failed to create directory: {e}'

    @desc('Rename a file or directory')
    def rename_path(self, arg=''):
        """
        重命名文件或目录。
        兼容：
        - 结构化参数：old_path + new_name / new_path
        """
        try:
            payload = self._decode_structured_arg(arg)
            if not isinstance(payload, dict):
                return 0, 'Invalid rename payload'

            old_path = self._resolve_target_path(payload.get('old_path', ''))
            new_name = (payload.get('new_name') or '').strip()
            new_path = (payload.get('new_path') or '').strip()

            if not os.path.exists(old_path):
                return 0, f'Path not found: {old_path}'

            if new_path:
                target_path = self._resolve_target_path(new_path)
            else:
                if not new_name:
                    return 0, 'New name is required'
                target_path = os.path.join(os.path.dirname(old_path), new_name)

            if os.path.exists(target_path):
                return 0, f'Target already exists: {target_path}'

            os.rename(old_path, target_path)
            return 1, f'Renamed to: {target_path}'
        except Exception as e:
            return 0, f'Failed to rename path: {e}'

    # ------------------ 压缩文件 ------------------ #
    @desc('Create a ZIP archive')
    def zip(self, dir_name):
        import pathlib
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

    @desc('Start a background job')
    def start_job(self, job_name: str):
        """
        启动后台任务。
        不传任务名时，列出可用任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            available_jobs = job_manager.list_available_jobs()
            if not available_jobs:
                return 1, 'No job modules available'
            return 1, '\n'.join(available_jobs)

        try:
            self._send_interim_result(1, f'Preparing background job: {job_name}')
            runtime = job_manager.start_job(job_name, self.command_id)

            self._send_final_result(
                1,
                f'Background job started: {runtime.display_name}\n'
                f'Thread: {runtime.thread.name}\n'
                f'Use "stop_job {runtime.job_key}" to request stop'
            )
        except Exception as e:
            return 0, f'Failed to start background job: {e}'

    @desc('Stop a background job')
    def stop_job(self, job_name: str):
        """
        停止后台任务。
        不传任务名时，列出当前运行中的任务。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager

        if not job_name:
            running_jobs = job_manager.list_running_jobs()
            if not running_jobs:
                return 1, 'No background jobs are currently running'
            return 1, '\n'.join(running_jobs)

        try:
            runtime = job_manager.stop_job(job_name)
            return 1, f'Stop request sent: {runtime.display_name}'
        except Exception as e:
            return 0, f'Failed to stop background job: {e}'

    @desc('List running background jobs')
    def jobs(self):
        """
        列出当前运行中的后台任务。
        """
        job_manager = self.socket.job_manager
        running_jobs = job_manager.list_running_jobs()
        if not running_jobs:
            return 1, 'No background jobs are currently running'
        return 1, '\n'.join(running_jobs)

    @desc('Show background job status')
    def job_status(self, job_name: str):
        """
        查看指定后台任务状态。
        """
        job_name = job_name.strip()
        job_manager = self.socket.job_manager
        if not job_name:
            return 0, 'Usage: job_status <job_name>'

        try:
            status_info = job_manager.get_job_status(job_name)
            return 1, format_dict(status_info)
        except Exception as e:
            return 0, f'Failed to query background job status: {e}'

    @desc('Stop all background jobs')
    def stop_all_jobs(self):
        """
        停止所有后台任务。
        """
        try:
            job_manager = self.socket.job_manager
            stopped_jobs = job_manager.stop_all_jobs()
            if not stopped_jobs:
                return 1, 'No background jobs are currently running'
            return 1, 'Stop request sent for:\n' + '\n'.join(stopped_jobs)
        except Exception as e:
            return 0, f'Failed to stop background jobs: {e}'

    @desc('Show command manifest as JSON payload')
    def command_manifest(self):
        methods = self._get_exported_command_methods()
        payload = [
            {
                'name': name,
                'help': method.help,
            }
            for name, method in methods.items()
        ]
        payload.sort(key=lambda item: item['name'].lower())
        return 1, json.dumps(payload, ensure_ascii=False)