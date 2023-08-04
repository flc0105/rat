import glob
import json
import os
import shlex
from functools import partial

from common.util import scan_args, get_time, format_dict
from server.config.config import SCRIPT_PATH
from server.util.util import secure_filename, replace_spaces


class Command:
    def __init__(self, conn, server):
        self.conn = conn
        self.server = server

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
        scripts = []
        if not filename:
            for file in glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True):
                scripts.append(os.path.relpath(file, SCRIPT_PATH).replace('\\', '/'))
            yield 1, '\n'.join(scripts)
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
                raise RuntimeError(f'Unprocessable file: {script_name}')

    def history(self, arg):
        """
        显示历史记录
        :param arg: -f 显示详细信息 -c 清除记录
        """
        if arg in ['-f', '--full']:
            yield 1, json.dumps(self.conn.history, ensure_ascii=False, indent=2)
        elif arg in ['-c', '--clear']:
            self.conn.history.clear()
            yield 1, 'History cleared'
        else:
            yield 1, '\n'.join([cmd['command'] for cmd in self.conn.history])

    def save_result(self, command):
        """
        将命令结果写入本地文件
        """
        if not command:
            return 0, ''
        func = self.server.process_command(command, self.conn, Command(self.conn, self.server))
        filename = f'{replace_spaces(secure_filename(command))}_{self.conn.address[0]}_{get_time()}.txt'
        with open(filename, 'wt') as f:
            for i in func():
                f.write(i[1] + '\n')
        yield 1, 'Result saved to {}'.format(filename)

    def alias(self, arg):
        # 显示别名列表
        if not arg:
            yield 1, format_dict(self.server.aliases)
            return
        # 没有等号
        equal_mark_index = arg.find('=')
        if equal_mark_index == -1:
            raise SyntaxError('missing equal mark')
        # 拆分
        alias = arg[0:equal_mark_index].strip()
        cmd = arg[equal_mark_index + 1:].strip()
        # 判断是否有空值
        if not all([alias, cmd]):
            raise SyntaxError('null value not accepted')
        self.server.aliases[alias] = cmd
        self.server.save_aliases()
        yield 1, f'Alias added: {alias} -> {cmd}'

    def unalias(self, arg):
        if not arg:
            raise SyntaxError('missing alias name')
        if arg not in self.server.aliases:
            raise SyntaxError(f'alias does not exist: {arg}')
        self.server.aliases.pop(arg)
        self.server.save_aliases()
        yield 1, f'Alias removed: {arg}'
