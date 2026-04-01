import json
import re
import shlex

from server.config.config import ALIAS_PATH


class AliasManager:
    PLACEHOLDER_PATTERN = r'<.*?>'

    def __init__(self):
        self.alias_path = ALIAS_PATH
        self.aliases = {}
        self.load_aliases()

    # ------------------ 持久化 ------------------ #
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
            json.dump(aliases, file_obj, indent=2)

    def load_aliases(self):
        """从文件中加载命令别名"""
        try:
            self.aliases = self._read_alias_file()
        except (FileNotFoundError, json.JSONDecodeError):
            self.aliases = {}

    def save_aliases(self):
        """保存命令别名到文件"""
        self._write_alias_file(self.aliases)

    # ------------------ 基础操作 ------------------ #
    def add_alias(self, alias, command):
        """添加别名"""
        if not alias or not command:
            raise ValueError("Alias and command cannot be empty")
        self.aliases[alias] = command
        self.save_aliases()

    def remove_alias(self, alias):
        """移除别名"""
        if alias not in self.aliases:
            raise KeyError(f"Alias '{alias}' does not exist")
        del self.aliases[alias]
        self.save_aliases()

    def list_aliases(self):
        """返回格式化的别名列表"""
        return self.aliases.copy()

    # ------------------ 参数解析 ------------------ #
    def _get_alias_template(self, alias):
        """
        获取别名模板命令
        """
        command = self.aliases.get(alias)
        if not command:
            raise KeyError(f"Alias '{alias}' not found")
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

    def get_alias_command(self, alias, args=""):
        """获取别名对应的命令，并替换参数"""
        command = self._get_alias_template(alias)
        required_args = self._extract_required_args(command)
        provided_args = self._parse_provided_args(args)

        self._validate_alias_args(required_args, provided_args)
        return self._replace_placeholders(command, provided_args)


