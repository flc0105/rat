import base64
import glob
import json
import os
import re
import shlex

from core.utils.command_output import (
    StructuredCommandResult,
    parse_output_format,
    render_structured_result,
)
from core.utils.formatting import format_dict
from core.utils.parsing import scan_args
from core.utils.script_metadata import read_script_metadata_from_file
from server.application.command.command_execution_event import CommandExecutionEvent
from server.application.history.history_record_policy import CommandHistoryRecordPolicy
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

        event_iter = self.remote_execution_service.iter_upload_events(
            self.conn,
            filename,
            remote_path='',
            history_entry_id=history_entry_id,
            source='cli',
            task_id='',
            command=f'upload {os.path.basename(filename)}',
        )

        for event in event_iter:
            if event.event_type == CommandExecutionEvent.STARTED:
                continue

            if event.event_type == CommandExecutionEvent.COMPLETED:
                continue

            if event.event_type == CommandExecutionEvent.PROGRESS:
                if event.text:
                    yield 1, event.text
                continue

            if event.event_type == CommandExecutionEvent.CHUNK:
                yield event.status, event.text
                continue

            if event.event_type == CommandExecutionEvent.ERROR:
                yield 0, event.text
                continue

            if event.event_type == CommandExecutionEvent.CANCELLED:
                if event.payload.get('terminal'):
                    continue
                yield 0, event.text or 'cancelled'


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

    def list_script_catalog(self):
        items = []
        for file_path in self._iter_script_files():
            rel_path = os.path.relpath(file_path, SCRIPT_PATH).replace('\\', '/')
            script_name = rel_path[:-3] if rel_path.endswith('.py') else rel_path
            metadata = read_script_metadata_from_file(file_path, fallback_name=script_name)
            items.append({
                'script_name': script_name,
                'path': rel_path,
                'display_name': str(metadata.get('display_name') or script_name.split('/')[-1]).strip() or script_name,
                'description': str(metadata.get('description') or '').strip(),
                'metadata': metadata,
            })
        return sorted(items, key=lambda item: item.get('path', '').lower())

    def _resolve_script_path(self, script_name: str) -> str:
        script_path = os.path.abspath(os.path.join(SCRIPT_PATH, script_name))
        if os.path.isfile(script_path):
            return script_path

        if os.path.isfile(script_path + '.py'):
            return script_path + '.py'

        raise FileNotFoundError(f"Script not found: {script_path}")

    def _build_script_plan(self, script_text: str, script_args: list):
        return self.plan_builder.build_script_plan(script_text, scan_args(script_args))

    def _decode_script_payload_arg(self, raw):
        text = str(raw or '').strip()
        prefix = '__json__:'
        if not text.startswith(prefix):
            raise ValueError('Invalid run_script payload')
        encoded = text[len(prefix):]
        try:
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode('utf-8')
            return json.loads(decoded)
        except Exception as e:
            raise ValueError(f'Invalid run_script payload: {e}')

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

    def execute_script_payload(self, payload_text: str):
        payload = self._decode_script_payload_arg(payload_text)
        if not isinstance(payload, dict):
            raise ValueError('Invalid run_script payload')

        script_name = str(payload.get('script_name') or payload.get('name') or '').strip()
        if not script_name:
            raise ValueError('script_name is required')

        params = payload.get('params') or {}
        if not isinstance(params, dict):
            raise ValueError('params must be an object')

        script_path = self._resolve_script_path(script_name)
        plan_executor = self.plan_executor_factory()

        with open(script_path, 'rt', encoding='utf-8') as file_obj:
            try:
                plan = self.plan_builder.build_script_plan(file_obj.read(), params)
                for item in plan_executor(plan)():
                    yield item
            except UnicodeDecodeError:
                raise RuntimeError(f"Unable to read file: {script_path}")


class AliasBuiltinSupport:
    """
    alias / unalias 相关内建命令支持。
    """

    PLATFORM_OPTION_PATTERN = re.compile(r'^(?:--platform|-p)\s+(all|common|win|mac)\b', re.IGNORECASE)

    def __init__(self, alias_manager, conn):
        self.alias_manager = alias_manager
        self.conn = conn

    # add alias平台选项解析 2026-04-08
    def _parse_platform_option(self, arg_text: str) -> tuple[str, str]:
        text = str(arg_text or '').strip()
        matched = self.PLATFORM_OPTION_PATTERN.match(text)
        if matched is None:
            return '', text

        platform_name = matched.group(1).lower()
        remaining = text[matched.end():].strip()
        return platform_name, remaining

    def list_aliases(self):
        return self.alias_manager.list_aliases(conn=self.conn)

    def alias(self, arg):
        arg_text = str(arg or '').strip()
        platform_name, remaining_text = self._parse_platform_option(arg_text)
        target_platform = platform_name or 'common'

        if not remaining_text:
            payload = self.alias_manager.list_aliases_for_platform(platform_name, conn=self.conn)
            # yield 1, format_dict(payload)
            if platform_name == 'all':
                yield 1, self._format_grouped_aliases(payload)
            else:
                yield 1, format_dict(payload)
            return

        if remaining_text.lower() == 'reload':
            self.alias_manager.load_aliases()
            yield 1, 'Aliases reloaded'
            return

        if remaining_text in ('--json', 'json'):
            payload = self.alias_manager.list_aliases_for_platform(platform_name, conn=self.conn)
            yield 1, json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            )
            return

        try:
            if '=' in remaining_text:
                if target_platform == 'all':
                    raise ValueError("Platform all is query-only and cannot be used to save alias")

                alias_name, command_text = [part.strip() for part in remaining_text.split('=', 1)]
                self.alias_manager.add_alias(alias_name, command_text, platform=target_platform)
                yield 1, f'Alias saved [{target_platform}]: {alias_name} -> {command_text}'
            else:
                raise ValueError("Expected format: alias [--platform win|mac|common] name = command")
        except Exception as e:
            raise ValueError(f'Failed to save alias: {e}')

    def _format_grouped_aliases(self, payload: dict) -> str:
        lines = []
        for platform_name in ('common', 'win', 'mac'):
            alias_map = payload.get(platform_name) or {}
            lines.append(f'[{platform_name}]')
            if not alias_map:
                lines.append('(empty)')
            else:
                for alias_name, command_text in alias_map.items():
                    lines.append(f'{alias_name} = {command_text}')
            lines.append('')
        return '\n'.join(lines).rstrip()

    def unalias(self, arg):
        if not arg:
            raise ValueError("Missing alias name")

        platform_name, remaining_text = self._parse_platform_option(arg)
        alias_name = remaining_text.strip()
        if not alias_name:
            raise ValueError("Missing alias name")

        try:
            target_platform = platform_name or 'common'
            self.alias_manager.remove_alias(alias_name, platform=target_platform)
            yield 1, f"Alias removed [{target_platform}]: {alias_name}"
        except KeyError:
            raise ValueError(f"Alias not found: {alias_name}")


class PinnedPathBuiltinSupport:
    """
    gopin 相关内建命令支持。
    """

    def __init__(self, pinned_path_store, command_history, conn, history_entry_id_provider, command_processor_factory):
        self.pinned_path_store = pinned_path_store
        self.command_history = command_history
        self.conn = conn
        self.history_entry_id_provider = history_entry_id_provider
        self.command_processor_factory = command_processor_factory

    # add gopin 快速跳转 2026-04-09 15:30
    def _get_hostname(self) -> str:
        session_info = getattr(self.conn, 'session_info', None)
        return getattr(session_info, 'hostname', '') or 'unknown_host'

    # add gopin 快速跳转 2026-04-09 15:30
    def list_pinned_paths(self) -> list[dict]:
        return self.pinned_path_store.list_items(self._get_hostname())

    # add gopin 快速跳转 2026-04-09 15:30
    def _build_cd_command(self, path: str) -> str:
        return f'cd {path}'

    # add gopin 快速跳转 2026-04-09 15:30
    def gopin(self, arg=''):
        name = str(arg or '').strip()
        items = self.list_pinned_paths()

        if not name:
            if not items:
                yield 1, 'No saved pinned paths for current host'
                return

            lines = [f'[{self._get_hostname()}]']
            for item in items:
                lines.append(f'{item.get("display_name", "")} -> {item.get("path", "")}')
            yield 1, '\n'.join(lines)
            return

        matched_item = self.pinned_path_store.get_item_by_name(self._get_hostname(), name)
        if matched_item is None:
            raise ValueError(f'Pinned path not found: {name}')

        target_path = str(matched_item.get('path') or '').strip()
        resolved_command = self._build_cd_command(target_path)

        # gopin 作为快捷命令，history 保留原始 gopin 输入，不再改写成 cd 结果。
        yield 1, f'gopin {name} -> {resolved_command}'

        command_processor = self.command_processor_factory()
        executor = command_processor(resolved_command)
        for item in executor():
            yield item


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
        return CommandHistoryRecordPolicy.is_history_replay_command(text)

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

            yield 1, '\n'.join(lines)
            yield 1, '\nTip: use history run <index> or !<index> to run a history item quickly'
            return

        if arg_text == 'clear':
            self.command_history.clear_history_for_connection(self.conn)
            yield 1, 'Command history cleared'
            return

        matched = self.HISTORY_RUN_PATTERN.fullmatch(arg_text)
        if matched:
            history_index = int(matched.group(1))
            for item in self._run_history_item(history_index):
                yield item
            return

        raise ValueError('Unsupported history command. Use: history | history run <index> | history clear')


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

        output_format = parse_output_format(arg)

        yield render_structured_result(
            StructuredCommandResult(
                status=1,
                data=payload,
                shape='dict',
                width=24,
            ),
            output_format=output_format,
        )
