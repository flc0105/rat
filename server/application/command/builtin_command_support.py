import base64
import glob
import json
import os
import re
import shlex

from core.utils.command_output import (
    StructuredCommandResult,
    parse_output_format,
    render_structured_result, strip_output_format_arg,
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



import re

from core.utils.command_output import (
    StructuredCommandResult,
    parse_output_format,
    render_structured_result,
    strip_output_format_arg,
)


import re

from core.utils.command_output import (
    StructuredCommandResult,
    parse_output_format,
    render_structured_result,
    strip_output_format_arg,
)


class AliasBuiltinSupport:
    """
    alias 子命令支持：

    - alias / alias resolve
    - alias set [--platform common|win|mac|linux] name = command
    - alias unset [--platform common|win|mac|linux] name
    - alias list [--platform common|win|mac|linux] [--json]
    - alias reload
    """

    VALID_PLATFORMS = ('common', 'win', 'mac', 'linux')

    PLATFORM_OPTION_PATTERN = re.compile(
        r'^(?:--platform|-p)\s+(common|win|mac|linux)\b',
        re.IGNORECASE,
    )

    ANY_PLATFORM_OPTION_PATTERN = re.compile(
        r'^(?:--platform|-p)\s+(\S+)\b',
        re.IGNORECASE,
    )

    SUBCOMMAND_PATTERN = re.compile(
        r'^(resolve|set|unset|list|reload)\b',
        re.IGNORECASE,
    )

    def __init__(self, alias_manager, conn):
        self.alias_manager = alias_manager
        self.conn = conn

    def _parse_platform_option(self, arg_text: str) -> tuple[str, str]:
        text = str(arg_text or '').strip()
        matched = self.PLATFORM_OPTION_PATTERN.match(text)
        if matched is not None:
            platform_name = matched.group(1).lower()
            remaining = text[matched.end():].strip()
            return platform_name, remaining

        any_matched = self.ANY_PLATFORM_OPTION_PATTERN.match(text)
        if any_matched is not None:
            invalid_platform = any_matched.group(1)
            raise ValueError(
                f"Unsupported platform: {invalid_platform}. "
                f"Supported platforms: {', '.join(self.VALID_PLATFORMS)}"
            )

        return '', text

    def _resolve_target_platform(self, platform_name: str) -> str:
        return platform_name or 'common'

    def _parse_subcommand(self, arg_text: str) -> tuple[str, str]:
        text = str(arg_text or '').strip()
        if not text:
            return 'resolve', ''

        matched = self.SUBCOMMAND_PATTERN.match(text)
        if matched is None:
            return 'resolve', text

        subcommand = matched.group(1).lower()
        remaining = text[matched.end():].strip()
        return subcommand, remaining

    def _get_runtime_platform(self) -> str:
        """
        直接复用 AliasManager 的连接平台识别逻辑。
        如果是 ios/android/unknown，返回空串，resolve 时只显示 common。
        """
        platform_name = self.alias_manager.get_platform_for_connection(self.conn)
        if platform_name in self.VALID_PLATFORMS:
            return platform_name
        return ''

    def _normalize_alias_rows(self, alias_map: dict, platform_name: str) -> list[dict]:
        rows = []
        for alias_name in sorted((alias_map or {}).keys()):
            rows.append({
                'platform': platform_name,
                'alias': alias_name or '',
                'command': alias_map.get(alias_name) or '',
            })
        return rows

    def _build_resolved_alias_payload(self) -> list[dict]:
        """
        alias resolve:
        - 显示 common + 当前平台
        - 当前平台无法识别时，只显示 common
        - platform 字段表示“该 alias 最终来自哪一层”
        """
        runtime_platform = self._get_runtime_platform()

        common_aliases = self.alias_manager.list_aliases_for_platform('common', conn=self.conn) or {}
        platform_aliases = {}

        if runtime_platform and runtime_platform != 'common':
            platform_aliases = self.alias_manager.list_aliases_for_platform(runtime_platform, conn=self.conn) or {}

        merged = dict(common_aliases)
        merged.update(platform_aliases)

        rows = []
        for alias_name, command_text in merged.items():
            source_platform = runtime_platform if runtime_platform and alias_name in platform_aliases else 'common'
            rows.append({
                'platform': source_platform,
                'alias': alias_name or '',
                'command': command_text or '',
            })

        rows.sort(key=lambda item: (
            str(item.get('platform') or ''),
            str(item.get('alias') or ''),
        ))
        return rows

    def _build_list_alias_payload(self, platform_name: str = '') -> list[dict]:
        """
        alias list:
        - 默认显示所有平台原始配置
        - 支持 --platform common|win|mac|linux
        - 不支持 --platform all
        """
        if platform_name:
            alias_map = self.alias_manager.list_aliases_for_platform(platform_name, conn=self.conn) or {}
            return self._normalize_alias_rows(alias_map, platform_name)

        grouped = self.alias_manager.list_aliases_grouped() or {}
        rows = []

        for current_platform in self.VALID_PLATFORMS:
            alias_map = grouped.get(current_platform) or {}
            rows.extend(self._normalize_alias_rows(alias_map, current_platform))

        return rows

    def list_aliases(self):
        """
        给自动补全/旧逻辑使用：返回当前连接可用 alias（dict）
        """
        return self.alias_manager.list_aliases(conn=self.conn)

    def list_resolved_aliases(self) -> list[dict]:
        """
        给自动补全/展示使用：返回 common + 当前平台 合并后的结构化结果
        """
        return self._build_resolved_alias_payload()

    def _render_table_result(self, payload: list[dict], output_format: str):
        return render_structured_result(
            StructuredCommandResult(
                status=1,
                data=payload,
                shape='table',
            ),
            output_format=output_format,
        )

    def _alias_resolve(self, arg=''):
        output_format = parse_output_format(arg)
        arg = strip_output_format_arg(arg)

        if str(arg or '').strip():
            raise ValueError("alias resolve does not accept any arguments")

        payload = self._build_resolved_alias_payload()
        yield self._render_table_result(payload, output_format)

    def _alias_set(self, arg=''):
        text = str(arg or '').strip()
        platform_name, remaining_text = self._parse_platform_option(text)
        target_platform = self._resolve_target_platform(platform_name)

        if not remaining_text or '=' not in remaining_text:
            raise ValueError(
                "Expected format: alias set [--platform common|win|mac|linux] name = command"
            )

        try:
            alias_name, command_text = [part.strip() for part in remaining_text.split('=', 1)]

            if not alias_name:
                raise ValueError("Missing alias name")
            if not command_text:
                raise ValueError("Missing alias command")

            self.alias_manager.add_alias(alias_name, command_text, platform=target_platform)
            yield 1, f'Alias saved [{target_platform}]: {alias_name} -> {command_text}'
        except Exception as e:
            raise ValueError(f'Failed to save alias: {e}')

    def _alias_unset(self, arg=''):
        text = str(arg or '').strip()
        platform_name, remaining_text = self._parse_platform_option(text)
        target_platform = self._resolve_target_platform(platform_name)

        alias_name = remaining_text.strip()
        if not alias_name:
            raise ValueError("Missing alias name")

        try:
            self.alias_manager.remove_alias(alias_name, platform=target_platform)
            yield 1, f"Alias removed [{target_platform}]: {alias_name}"
        except KeyError:
            raise ValueError(f"Alias not found: {alias_name}")

    def _alias_list(self, arg=''):
        output_format = parse_output_format(arg)
        arg = strip_output_format_arg(arg)

        platform_name, remaining_text = self._parse_platform_option(arg)
        if remaining_text:
            raise ValueError(
                "Expected format: alias list [--platform common|win|mac|linux] [--json]"
            )

        payload = self._build_list_alias_payload(platform_name=platform_name)
        yield self._render_table_result(payload, output_format)

    def _alias_reload(self, arg=''):
        text = str(arg or '').strip()
        if text:
            raise ValueError("alias reload does not accept any arguments")

        self.alias_manager.load_aliases()
        yield 1, 'Aliases reloaded'

    def alias(self, arg=''):
        subcommand, remaining = self._parse_subcommand(arg)

        if subcommand == 'resolve':
            for item in self._alias_resolve(remaining):
                yield item
            return

        if subcommand == 'set':
            for item in self._alias_set(remaining):
                yield item
            return

        if subcommand == 'unset':
            for item in self._alias_unset(remaining):
                yield item
            return

        if subcommand == 'list':
            for item in self._alias_list(remaining):
                yield item
            return

        if subcommand == 'reload':
            for item in self._alias_reload(remaining):
                yield item
            return

        raise ValueError(
            "Unsupported alias subcommand. "
            "Use: alias [resolve] | alias set | alias unset | alias list | alias reload"
        )


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


    def _get_machine_id(self) -> str:
        session_info = getattr(self.conn, 'session_info', None)
        return getattr(session_info, 'machine_id', '') or 'unknown_machine'


    def list_pinned_paths(self) -> list[dict]:
        return self.pinned_path_store.list_items(self._get_machine_id())


    def _build_cd_command(self, path: str) -> str:
        return f'cd {path}'


    def gopin(self, arg=''):
        name = str(arg or '').strip()
        items = self.list_pinned_paths()

        if not name:
            if not items:
                yield 1, 'No saved pinned paths for current host'
                return

            lines = [f'[{self._get_machine_id()}]']
            for item in items:
                lines.append(f'{item.get("display_name", "")} -> {item.get("path", "")}')
            yield 1, '\n'.join(lines)
            return

        matched_item = self.pinned_path_store.get_item_by_name(self._get_machine_id(), name)
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
        arg = strip_output_format_arg(arg)

        yield render_structured_result(
            StructuredCommandResult(
                status=1,
                data=payload,
                shape='dict',
                width=24,
            ),
            output_format=output_format,
        )


class ExternalToolCliBuiltinSupport:
    """
    xt 轻量 CLI 门面。

    约束：
    - 只解析 package.execs 的原生 exec name
    - 不提供 install；安装仍属于 package/web external tool 管理
    - 执行时只运行已安装 package exec，并把原始参数追加到 argv
    """

    RESERVED_SUBCOMMANDS = {'list', 'info', 'which', 'run', 'help'}

    def __init__(self, server, conn, command_processor_factory):
        self.server = server
        self.conn = conn
        self.command_processor_factory = command_processor_factory

    def _catalog_service(self):
        web_service = getattr(self.server, 'web_service', None)
        assembly = getattr(web_service, 'assembly', None)
        service = getattr(assembly, 'external_tool_catalog_service', None)
        if service is None:
            raise RuntimeError('external tool catalog service is not available')
        return service

    def _runtime_service(self):
        web_service = getattr(self.server, 'web_service', None)
        assembly = getattr(web_service, 'assembly', None)
        service = getattr(assembly, 'external_tool_runtime_service', None)
        if service is None:
            raise RuntimeError('external tool runtime service is not available')
        return service

    def _client_platform(self) -> str:
        info = getattr(self.conn, 'session_info', None)
        value = getattr(info, 'os_alias', '') if info is not None else ''
        return self._catalog_service()._normalize_platform(value or '')

    def _client_arch(self) -> str:
        info = getattr(self.conn, 'session_info', None)
        return str(getattr(info, 'arch', '') if info is not None else '').strip().lower()

    def _client_cwd(self) -> str:
        info = getattr(self.conn, 'session_info', None)
        return str(getattr(info, 'cwd', '') if info is not None else '').strip()

    def _encode_payload_arg(self, payload: dict) -> str:
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        return f'__json__:{encoded}'

    def _split_first_token(self, text: str) -> tuple[str, str]:
        raw = str(text or '').strip()
        if not raw:
            return '', ''
        parts = raw.split(None, 1)
        first = parts[0].strip()
        rest = parts[1].strip() if len(parts) > 1 else ''
        return first, rest

    def _strip_raw_arg_separator(self, text: str) -> str:
        raw = str(text or '').strip()
        if raw == '--':
            return ''
        if raw.startswith('-- '):
            return raw[3:].strip()
        return raw

    def _resolve_alias(self, alias: str) -> dict:
        return self._catalog_service().resolve_cli_alias(
            alias,
            side='client',
            platform_alias=self._client_platform(),
            arch=self._client_arch(),
        )

    def _build_client_payload(self, target: dict, raw_args: str = '') -> dict:
        runtime_service = self._runtime_service()
        payload = runtime_service.build_client_exec_payload(
            target,
            raw_args=self._strip_raw_arg_separator(raw_args),
            platform_alias=self._client_platform(),
            arch=self._client_arch(),
            cwd=self._client_cwd(),
        )
        return payload

    def _iter_nested_command(self, command_text: str):
        command_processor = self.command_processor_factory()
        executor = command_processor(command_text)
        for item in executor():
            yield item

    def _format_cli_list(self) -> str:
        catalog = self._catalog_service()
        items = catalog.list_cli_aliases(
            side='client',
            platform_alias=self._client_platform(),
            arch=self._client_arch(),
        )

        if not items:
            return 'No external tool execs available. Add execs to external tool package meta.'

        rows = []
        for item in items:
            rows.append({
                'alias': item.get('alias') or '',
                'exec': item.get('exec_name') or item.get('alias') or '',
                'package_id': item.get('package_id') or item.get('tool_id') or '',
                'display_name': item.get('display_name') or '',
                'package_key': item.get('package_key') or '',
                'executable': item.get('executable_rel_path') or '',
            })

        return json.dumps({'items': rows}, ensure_ascii=False, indent=2)

    def _format_info(self, alias: str) -> str:
        target = self._resolve_alias(alias)
        meta = target.get('meta') or {}
        cli = target.get('cli') or {}
        payload = self._build_client_payload(target, raw_args='')
        install = payload.get('install') or {}
        package_payload = payload.get('package') or {}

        return json.dumps({
            'exec': target.get('exec_name') or target.get('alias') or alias,
            'package_id': meta.get('id') or '',
            'display_name': meta.get('display_name') or '',
            'description': target.get('description') or meta.get('description') or '',
            'side': 'client',
            'platforms': meta.get('platforms') or [],
            'arch': meta.get('arch') or '',
            'package_key': payload.get('package_key') or target.get('package_key') or '',
            'cli': {
                'enabled': bool(cli.get('enabled', True)),
                'exec_name': target.get('exec_name') or target.get('alias') or alias,
                'arg_mode': cli.get('arg_mode') or 'raw_append',
            },
            'package': {
                'filename': package_payload.get('filename') or '',
                'executable_rel_path': package_payload.get('executable_rel_path') or '',
            },
            'install': {
                'install_dir': install.get('install_dir') or '',
                'skip_if_exists': install.get('skip_if_exists') or '',
            },
            'usage': f'xt {target.get("exec_name") or alias} <raw args>',
        }, ensure_ascii=False, indent=2)

    def _which(self, alias: str):
        target = self._resolve_alias(alias)
        payload = self._build_client_payload(target, raw_args='')
        command = f'external_tool_which {self._encode_payload_arg(payload)}'
        for item in self._iter_nested_command(command):
            yield item

    def _run_alias(self, alias: str, raw_args: str):
        target = self._resolve_alias(alias)
        payload = self._build_client_payload(target, raw_args=raw_args)
        command = f'external_tool_exec {self._encode_payload_arg(payload)}'
        for item in self._iter_nested_command(command):
            yield item

    def xt(self, arg=''):
        arg_text = str(arg or '').strip()

        if not arg_text or arg_text == 'list':
            yield 1, self._format_cli_list()
            return

        if arg_text in ('help', '-h', '--help'):
            yield 1, 'Usage: xt list | xt info <exec> | xt which <exec> | xt <exec> [--] <raw args>'
            return

        subcommand, rest = self._split_first_token(arg_text)

        if subcommand == 'info':
            alias, _ = self._split_first_token(rest)
            if not alias:
                raise ValueError('Usage: xt info <exec>')
            yield 1, self._format_info(alias)
            return

        if subcommand == 'which':
            alias, _ = self._split_first_token(rest)
            if not alias:
                raise ValueError('Usage: xt which <exec>')
            for item in self._which(alias):
                yield item
            return

        if subcommand == 'install':
            raise ValueError('xt install is intentionally not supported. Install external tool packages from External Tool Manager.')

        if subcommand == 'run':
            alias, raw_args = self._split_first_token(rest)
            if not alias:
                raise ValueError('Usage: xt run <exec> [--] <raw args>')
            for item in self._run_alias(alias, raw_args):
                yield item
            return

        alias = subcommand
        raw_args = rest
        for item in self._run_alias(alias, raw_args):
            yield item