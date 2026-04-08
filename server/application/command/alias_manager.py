import json
import re
import shlex

from server.config.config import ALIAS_PATH


class AliasManager:
    PLACEHOLDER_PATTERN = r'<.*?>'
    SUPPORTED_PLATFORMS = ('common', 'win', 'mac')
    OS_PLATFORM_MAP = {
        'windows': 'win',
        'win': 'win',
        'darwin': 'mac',
        'mac': 'mac',
        'macos': 'mac',
    }
    QUERY_PLATFORMS = SUPPORTED_PLATFORMS + ('all',)

    def __init__(self):
        self.alias_path = ALIAS_PATH
        self.aliases = self._create_empty_aliases()
        self.load_aliases()

    # ------------------ 持久化 ------------------ #
    def _create_empty_aliases(self):
        return {
            'common': {},
            'win': {},
            'mac': {},
        }

    def _read_alias_file(self):
        """
        从别名文件中读取数据
        """
        with open(self.alias_path, 'r', encoding='utf-8') as file_obj:
            return json.load(file_obj)

    def _write_alias_file(self, aliases: dict):
        """
        将别名数据写入文件
        """
        with open(self.alias_path, 'w', encoding='utf-8') as file_obj:
            json.dump(aliases, file_obj, indent=2, ensure_ascii=False)

    # add alias平台归一化 2026-04-08
    def _normalize_platform(self, platform_name: str, allow_empty: bool = False, allow_all: bool = False) -> str:
        text = str(platform_name or '').strip().lower()
        if not text:
            if allow_empty:
                return ''
            return 'common'

        normalized = self.OS_PLATFORM_MAP.get(text, text)

        if allow_all and normalized == 'all':
            return 'all'

        if normalized not in self.SUPPORTED_PLATFORMS:
            raise ValueError(f'Unsupported platform: {platform_name}')
        return normalized

    # add alias配置结构归一化 2026-04-08
    def _normalize_alias_payload(self, payload) -> dict:
        normalized = self._create_empty_aliases()
        if not isinstance(payload, dict):
            return normalized

        has_group_keys = any(key in payload for key in self.SUPPORTED_PLATFORMS)
        if has_group_keys:
            for platform_name in self.SUPPORTED_PLATFORMS:
                platform_aliases = payload.get(platform_name) or {}
                if not isinstance(platform_aliases, dict):
                    continue

                normalized[platform_name] = {
                    str(alias_name).strip(): str(command_text)
                    for alias_name, command_text in platform_aliases.items()
                    if str(alias_name).strip() and str(command_text).strip()
                }
            return normalized

        normalized['common'] = {
            str(alias_name).strip(): str(command_text)
            for alias_name, command_text in payload.items()
            if str(alias_name).strip() and str(command_text).strip()
        }
        return normalized

    def load_aliases(self):
        """从文件中加载命令别名"""
        try:
            payload = self._read_alias_file()
            self.aliases = self._normalize_alias_payload(payload)
        except (FileNotFoundError, json.JSONDecodeError):
            self.aliases = self._create_empty_aliases()

    def save_aliases(self):
        """保存命令别名到文件"""
        self._write_alias_file(self.aliases)

    # ------------------ 平台解析 ------------------ #
    # add alias连接平台识别 2026-04-08
    def get_platform_for_connection(self, conn=None) -> str:
        session_info = getattr(conn, 'session_info', None)
        os_type = str(getattr(session_info, 'os_type', '') or '').strip().lower()
        return self._normalize_platform(os_type, allow_empty=True)

    # add alias当前连接可见列表 2026-04-08
    def get_effective_aliases(self, conn=None) -> dict:
        platform_name = self.get_platform_for_connection(conn)
        result = dict(self.aliases.get('common') or {})

        if platform_name and platform_name in self.aliases:
            result.update(self.aliases.get(platform_name) or {})

        return result

    # ------------------ 基础操作 ------------------ #
    def add_alias(self, alias, command, platform: str = 'common'):
        """添加别名"""
        alias_name = str(alias or '').strip()
        command_text = str(command or '').strip()
        platform_name = self._normalize_platform(platform)

        if not alias_name or not command_text:
            raise ValueError("Alias and command cannot be empty")

        self.aliases.setdefault(platform_name, {})
        self.aliases[platform_name][alias_name] = command_text
        self.save_aliases()

    def remove_alias(self, alias, platform: str = ''):
        """移除别名"""
        alias_name = str(alias or '').strip()
        if not alias_name:
            raise KeyError("Alias name cannot be empty")

        platform_name = self._normalize_platform(platform, allow_empty=True)
        removed = False
        target_platforms = (platform_name,) if platform_name else self.SUPPORTED_PLATFORMS

        for current_platform in target_platforms:
            alias_map = self.aliases.get(current_platform) or {}
            if alias_name not in alias_map:
                continue
            del alias_map[alias_name]
            removed = True

        if not removed:
            raise KeyError(f"Alias '{alias_name}' does not exist")

        self.save_aliases()

    def list_aliases(self, conn=None):
        """返回格式化的别名列表"""
        return self.get_effective_aliases(conn)

    # add alias全平台查询视图 2026-04-08
    def list_aliases_for_platform(self, platform: str, conn=None) -> dict:
        platform_name = self._normalize_platform(platform, allow_empty=True, allow_all=True)
        if platform_name == 'all':
            return self.list_aliases_grouped()
        if not platform_name:
            return self.list_aliases(conn=conn)
        return dict(self.aliases.get(platform_name) or {})

    # add alias全量配置读取 2026-04-08
    def list_aliases_grouped(self):
        return {
            platform_name: dict(self.aliases.get(platform_name) or {})
            for platform_name in self.SUPPORTED_PLATFORMS
        }

    # ------------------ 参数解析 ------------------ #
    def _get_alias_template(self, alias, conn=None):
        """
        获取别名模板命令
        """
        alias_name = str(alias or '').strip()
        command = self.get_effective_aliases(conn).get(alias_name)
        if not command:
            raise KeyError(f"Alias '{alias_name}' not found")
        return command

    def _extract_required_args(self, command: str):
        """
        提取命令模板中的占位参数
        """
        return re.findall(self.PLACEHOLDER_PATTERN, command)

    def _parse_provided_args(self, args=""):
        """
        解析用户实际传入的参数
        """
        return shlex.split(args) if args else []

    def _replace_placeholders(self, command: str, provided_args: list):
        """
        依次替换命令模板中的占位符
        """
        for arg in provided_args:
            command = re.sub(self.PLACEHOLDER_PATTERN, arg, command, count=1)
        return command

    def _validate_alias_args(self, required_args: list, provided_args: list):
        """
        校验 alias 所需参数与实际参数是否匹配
        """
        if required_args:
            if len(required_args) != len(provided_args):
                raise ValueError(f"Expected {len(required_args)} argument(s), got {len(provided_args)}")
            return

        if provided_args:
            raise ValueError('This alias does not accept arguments')

    # add alias解析详情返回 2026-04-08
    def resolve_alias(self, alias, args="", conn=None) -> dict:
        alias_name = str(alias or '').strip()
        command = self._get_alias_template(alias_name, conn=conn)
        required_args = self._extract_required_args(command)
        provided_args = self._parse_provided_args(args)

        self._validate_alias_args(required_args, provided_args)
        expanded_command = self._replace_placeholders(command, provided_args)
        return {
            'alias': alias_name,
            'command': expanded_command,
            'platform': self.get_platform_for_connection(conn) or 'common',
        }

    def get_alias_command(self, alias, args="", conn=None):
        """获取别名对应的命令，并替换参数"""
        return self.resolve_alias(alias, args=args, conn=conn)['command']
