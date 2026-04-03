import glob
import json
import os
import re
import shlex

from core.utils.formatting import format_dict
from core.utils.parsing import scan_args
from server.config.config import SCRIPT_PATH


class UploadBuiltinSupport:
    """
    upload 相关内建命令支持。
    """

    def __init__(self, conn, remote_execution_service, history_entry_id_provider):
        self.conn = conn
        self.remote_execution_service = remote_execution_service
        self.history_entry_id_provider = history_entry_id_provider

    def upload(self, filename):
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"File does not exist: {filename}")

        history_entry_id = self.history_entry_id_provider()
        yield from self.remote_execution_service.stream_upload(
            self.conn,
            filename,
            remote_path='',
            history_entry_id=history_entry_id
        )


class ScriptBuiltinSupport:
    """
    script/exec 相关内建命令支持。
    """

    def __init__(self, plan_builder, plan_executor_factory):
        self.plan_builder = plan_builder
        self.plan_executor_factory = plan_executor_factory

    def _iter_script_files(self):
        return glob.iglob(os.path.join(SCRIPT_PATH, '**/*.py'), recursive=True)

    def list_scripts(self):
        return [
            os.path.relpath(file_path, SCRIPT_PATH).replace('\\', '/')
            for file_path in self._iter_script_files()
        ]

    def _resolve_script_path(self, script_name: str) -> str:
        script_path = os.path.abspath(os.path.join(SCRIPT_PATH, script_name))
        if os.path.isfile(script_path):
            return script_path

        if os.path.isfile(script_path + '.py'):
            return script_path + '.py'

        raise FileNotFoundError(f"Script not found: {script_path}")

    def _build_script_plan(self, script_text: str, script_args: list):
        return self.plan_builder.build_script_plan(script_text, scan_args(script_args))

    def execute_script_file(self, filename: str):
        parts = shlex.split(filename)
        script_path = self._resolve_script_path(parts[0])
        plan_executor = self.plan_executor_factory()

        with open(script_path, 'rt', encoding='utf-8') as file_obj:
            try:
                plan = self._build_script_plan(file_obj.read(), parts[1:])
                for item in plan_executor(plan)():
                    yield item
            except UnicodeDecodeError:
                raise RuntimeError(f"Unable to read file: {script_path}")


class AliasBuiltinSupport:
    """
    alias / unalias 相关内建命令支持。
    """

    def __init__(self, alias_manager):
        self.alias_manager = alias_manager

    def list_aliases(self):
        return self.alias_manager.list_aliases()

    def alias(self, arg):
        arg_text = str(arg or '').strip()

        if not arg_text:
            yield 1, format_dict(self.alias_manager.list_aliases())
            return

        if arg_text in ('--json', 'json'):
            yield 1, json.dumps(
                self.alias_manager.list_aliases(),
                ensure_ascii=False,
                indent=2
            )
            return

        try:
            if '=' in arg_text:
                alias_name, command_text = [part.strip() for part in arg_text.split('=', 1)]
                self.alias_manager.add_alias(alias_name, command_text)
                yield 1, f'Alias saved: {alias_name} -> {command_text}'
            else:
                raise ValueError("Expected format: alias name = command")
        except Exception as e:
            raise ValueError(f'Failed to save alias: {e}')

    def unalias(self, arg):
        if not arg:
            raise ValueError("Missing alias name")

        try:
            self.alias_manager.remove_alias(arg)
            yield 1, f"Alias removed: {arg}"
        except KeyError:
            raise ValueError(f"Alias not found: {arg}")


class HistoryBuiltinSupport:
    """
    history 相关内建命令支持。
    """

    HISTORY_RUN_PATTERN = re.compile(r'^run\s+(\d+)$', re.IGNORECASE)
    HISTORY_SHORTCUT_PATTERN = re.compile(r'^!(\d+)$')

    def __init__(self, command_history, conn, history_entry_id_provider, command_processor_factory):
        self.command_history = command_history
        self.conn = conn
        self.history_entry_id_provider = history_entry_id_provider
        self.command_processor_factory = command_processor_factory

    def _is_meta_history_command(self, command_text: str) -> bool:
        text = str(command_text or '').strip()
        if not text:
            return False
        if self.HISTORY_SHORTCUT_PATTERN.fullmatch(text):
            return True
        if self.HISTORY_RUN_PATTERN.fullmatch(text):
            return True
        return False

    def _get_resolvable_quick_history(self) -> list:
        """
        获取可用于 history run 的 quick history 视图。

        这里会过滤掉 history run / !index 这类“元命令”，避免：
        - 当前正在执行的 history run 把 quick history index 顶掉
        - history replay 命令本身污染可执行历史列表
        """
        entries = self.command_history.get_history_for_connection(self.conn) or []
        filtered = []

        for item in entries:
            command_text = str(item.get('command') or '').strip()
            if self._is_meta_history_command(command_text):
                continue

            cloned = dict(item)
            cloned['index'] = len(filtered) + 1
            filtered.append(cloned)

        return filtered

    def _resolve_history_command_by_index(self, history_index: int) -> str:
        entries = self._get_resolvable_quick_history()

        for item in entries:
            current_index = int(item.get('index', 0) or 0)
            if current_index != history_index:
                continue

            command_text = str(item.get('command') or '').strip()
            if command_text:
                return command_text
            break

        raise ValueError(f'History index not found: {history_index}')

    def _rewrite_current_history_entry(self, resolved_command: str):
        """
        当前这次交互在 ratserver 中已经预先创建了 history entry。
        当用户执行 history run / !index 时，这里把当前 entry 改写成真实命令，
        避免历史最终保留元命令文本。
        """
        entry_id = (self.history_entry_id_provider() or '').strip()
        if not entry_id:
            return

        self.command_history.update_entry_command_for_connection(
            self.conn,
            entry_id,
            resolved_command,
        )

    def _run_history_item(self, history_index: int):
        resolved_command = self._resolve_history_command_by_index(history_index)
        self._rewrite_current_history_entry(resolved_command)

        yield 1, f'sending command: {resolved_command}'

        command_processor = self.command_processor_factory()
        executor = command_processor(resolved_command)
        for item in executor():
            yield item

    def history(self, arg):
        arg_text = (arg or '').strip()

        if not arg_text:
            entries = self._get_resolvable_quick_history()
            if not entries:
                yield 1, 'No command history available\n\nTip: use history run <index> or !<index> to run a history item quickly'
                return

            lines = []
            for item in entries:
                lines.append(
                    f'{item.get("index", 0):>3}  '
                    f'{item.get("command", "")}'
                )

            lines.append('')
            lines.append('Tip: use history run <index> or !<index> to run a history item quickly')
            yield 1, '\n'.join(lines)
            return

        if arg_text == 'clear':
            self.command_history.clear_history_for_connection(self.conn)
            yield 1, 'Command history cleared'
            return

        matched = self.HISTORY_RUN_PATTERN.fullmatch(arg_text)
        if matched is not None:
            history_index = int(matched.group(1))
            for item in self._run_history_item(history_index):
                yield item
            return

        raise ValueError('Usage: history | history clear | history run <index> | !<index>')


class RttBuiltinSupport:
    """
    rtt 相关内建命令支持。
    """

    def __init__(self, conn):
        self.conn = conn

    def rtt(self, arg=''):
        payload = {
            'connection_state': self.conn.context.connected_at and (
                'offline' if self.conn.context.disconnected_at else 'online'
            ) or 'unknown',
            'connected_at': self.conn.context.connected_at or '',
            'last_seen_at': self.conn.context.last_seen_at or '',
            'last_heartbeat_sent_at': self.conn.context.last_heartbeat_sent_at or '',
            'last_heartbeat_ack_at': self.conn.context.last_heartbeat_ack_at or '',
            'last_rtt_ms': self.conn.context.last_rtt_ms if self.conn.context.last_rtt_ms is not None else '',
            'last_heartbeat_id': self.conn.context.last_heartbeat_id if self.conn.context.last_heartbeat_id is not None else '',
        }
        arg_text = str(arg or '').strip().lower()
        output_json = arg_text in ('json', '--json')

        if output_json:
            yield 1, json.dumps(payload, ensure_ascii=False, indent=2)
            return

        yield 1, format_dict(payload, width=25)
        # yield 1, format_dict(payload, width=25)