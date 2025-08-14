import json
import re
import shlex

from server.config.config import ALIAS_PATH


class AliasManager:
    def __init__(self):
        self.alias_path = ALIAS_PATH
        self.aliases = {}
        self.load_aliases()

    def load_aliases(self):
        """从文件中加载命令别名"""
        try:
            with open(self.alias_path, 'r') as f:
                self.aliases = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.aliases = {}

    def save_aliases(self):
        """保存命令别名到文件"""
        with open(self.alias_path, 'w') as f:
            json.dump(self.aliases, f, indent=2)

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

    def get_alias_command(self, alias, args=""):
        """获取别名对应的命令，并替换参数"""
        command = self.aliases.get(alias)
        if not command:
            raise KeyError(f"Alias '{alias}' not found")

        # 替换参数
        regex = r'<.*?>'
        provided_args = shlex.split(args) if args else []  # 实际传入的参数
        required_args = re.findall(regex, command)  # 要求的参数

        if required_args:
            if len(required_args) != len(provided_args):  # 如果参数个数不一致
                raise ValueError(f"Expected {len(required_args)} arguments, got {len(provided_args)}")
            for arg in provided_args:
                command = re.sub(regex, arg, command, count=1)
        elif provided_args:  # 命令原型中没有参数 但传入了参数
            raise ValueError("No arguments expected for this alias")

        return command

    def list_aliases(self):
        """返回格式化的别名列表"""
        return self.aliases.copy()
