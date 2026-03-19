import glob
import os
import shlex
from functools import partial

from core.utils.formatting import format_dict
from core.utils.parsing import parse, scan_args
from server.application.command.command_plan_builder import CommandPlanBuilder
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.config.config import SCRIPT_PATH


class CommandExecutor:
    WEB_COMMAND_TEMPLATES = [
        {
            'name': 'upload',
            'template': 'upload ',
            'help': 'upload <local_file> | Upload a local file to the client',
            'source': 'server'
        },
        {
            'name': 'exec',
            'template': 'exec ',
            'help': 'exec <script.py> | Execute a server-side Python script on the client',
            'source': 'server'
        },
        {
            'name': 'alias',
            'template': 'alias ',
            'help': 'alias <name> = <command> | Save a command alias',
            'source': 'server'
        },
        {
            'name': 'unalias',
            'template': 'unalias ',
            'help': 'unalias <name> | Remove a command alias',
            'source': 'server'
        },
        {
            'name': 'history',
            'template': 'history',
            'help': 'Show de-duplicated command history for the current host',
            'source': 'server'
        },
        {
            'name': 'history',
            'template': 'history clear',
            'help': 'Clear command history for the current host',
            'source': 'server'
        },
    ]

    def __init__(self, conn, server):
        self.conn = conn
        self.server = server
        self.current_history_entry_id = ''
        self.remote_execution_service = RemoteExecutionService(server)
        self.plan_builder = CommandPlanBuilder(server.alias_manager)

    # ------------------ 通用结果工具 ------------------ #
    def _yield_error(self, error):
        """
        返回单条错误结果
        """
        yield 0, str(error)

    def _execute_remote_plan(self, plan: dict):
        return partial(
            self.remote_execution_service.stream_command,
            self.conn,
            plan.get('command', ''),
            command_type=plan.get('command_type', 'command'),
            extra=plan.get('extra'),
            history_entry_id=self.current_history_entry_id
        )

    # ------------------ 补全候选 ------------------ #
    def get_command_candidates(self):
        """
        获取服务端可提供的命令候选：
        - server 内建命令模板
        - exec 脚本
        - alias
        """
        candidates = [dict(item) for item in self.WEB_COMMAND_TEMPLATES]

        for script in self._list_scripts():
            candidates.append({
                'name': 'exec',
                'template': f'exec {script}',
                'help': f'Execute script: {script}',
                'source': 'script'
            })

        for alias_name, alias_command in self.server.alias_manager.list_aliases().items():
            candidates.append({
                'name': alias_name,
                'template': alias_name,
                'help': f'Alias -> {alias_command}',
                'source': 'alias'
            })

        return candidates

    # ------------------ 主命令入口 ------------------ #
    def _resolve_builtin_command(self, name, arg):
        """
        解析内置命令方法
        """
        if hasattr(self, name) and callable(getattr(self, name)):
            return partial(getattr(self, name), arg)
        return None

    def _resolve_alias_command(self, name, arg):
        """
        解析别名命令
        """
        try:
            plan = self.plan_builder.build_alias_plan(name, arg)
            if not plan:
                return None
            return self._execute_remote_plan(plan)
        except Exception as e:
            return partial(self._yield_error, e)

    def _resolve_default_command(self, raw_command):
        """
        默认透传原始命令到客户端
        """
        plan = self.plan_builder.build_default_plan(raw_command)
        return self._execute_remote_plan(plan)

    def _resolve_argument_command(self, raw_command):
        """
        解析并发送 acmd 实验命令
        """
        plan = self.plan_builder.build_argument_command_plan(raw_command)
        return self._execute_remote_plan(plan)

    def process_command(self, cmd, history_entry_id: str = ''):
        """
        处理命令，返回可执行的生成器函数
        """
        self.current_history_entry_id = (history_entry_id or '').strip()
        name, arg = parse(cmd)

        if self.plan_builder.is_argument_command(cmd):
            return self._resolve_argument_command(cmd)

        builtin_handler = self._resolve_builtin_command(name, arg)
        if builtin_handler:
            return builtin_handler

        alias_handler = self._resolve_alias_command(name, arg)
        if alias_handler:
            return alias_handler

        return self._resolve_default_command(cmd)

    # ------------------ upload ------------------ #
    def upload(self, filename):
        """
        上传文件到客户端
        """
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"File does not exist: {filename}")

        try:
            yield from self.remote_execution_service.stream_upload(
                self.conn,
                filename,
                remote_path='',
                history_entry_id=self.current_history_entry_id
            )
        except Exception:
            self.conn.pending_command_ids.clear()
            raise

    # ------------------ exec ------------------ #
    def _iter_script_files(self):
        """
        遍历脚本目录下的所有 Python 脚本
        """
        return glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True)

    def _list_scripts(self):
        """
        获取脚本列表
        """
        return [
            os.path.relpath(file_path, SCRIPT_PATH).replace('\\', '/')
            for file_path in self._iter_script_files()
        ]

    def _resolve_script_path(self, script_name: str) -> str:
        """
        解析脚本绝对路径；若缺少 .py 后缀则自动补全尝试
        """
        script_path = os.path.abspath(os.path.join(SCRIPT_PATH, script_name))
        if os.path.isfile(script_path):
            return script_path

        if os.path.isfile(script_path + '.py'):
            return script_path + '.py'

        raise FileNotFoundError(f"Script not found: {script_path}")

    def _build_script_plan(self, script_text: str, script_args: list):
        return self.plan_builder.build_script_plan(script_text, scan_args(script_args))

    def _execute_script_file(self, filename: str):
        """
        执行指定 Python 脚本
        """
        parts = shlex.split(filename)
        script_path = self._resolve_script_path(parts[0])

        with open(script_path, 'rt', encoding='utf-8') as file_obj:
            try:
                plan = self._build_script_plan(file_obj.read(), parts[1:])
                func = self._execute_remote_plan(plan)
                for item in func():
                    yield item
            except UnicodeDecodeError:
                raise RuntimeError(f"Unable to read file: {script_path}")

    def exec(self, filename):
        """
        执行 Python 脚本
        """
        if not filename:
            yield 1, '\n'.join(self._list_scripts())
            return

        for item in self._execute_script_file(filename):
            yield item

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
                alias_name, command_text = [part.strip() for part in arg.split('=', 1)]
                self.server.alias_manager.add_alias(alias_name, command_text)
                yield 1, f'Alias saved: {alias_name} -> {command_text}'
            else:
                raise ValueError("Expected format: alias name = command")
        except Exception as e:
            raise ValueError(f'Failed to save alias: {e}')

    def unalias(self, arg):
        """移除命令别名"""
        if not arg:
            raise ValueError("Missing alias name")

        try:
            self.server.alias_manager.remove_alias(arg)
            yield 1, f'Alias removed: {arg}'
        except KeyError:
            raise ValueError(f"Alias not found: {arg}")

    def history(self, arg):
        """
        查看 / 清空当前连接的命令历史
        用法：
        - history
        - history clear
        """
        arg_text = (arg or '').strip()

        if not arg_text:
            entries = self.server.command_history.get_history_for_connection(self.conn)
            if not entries:
                yield 1, 'No command history available'
                return

            lines = []
            for item in entries:
                lines.append(
                    f'{item.get("index", 0):>3}  '
                    f'{item.get("command", "")}'
                )

            yield 1, '\n'.join(lines)
            return

        if arg_text == 'clear':
            self.server.command_history.clear_history_for_connection(self.conn)
            yield 1, 'Command history cleared'
            return

        raise ValueError('Usage: history | history clear')