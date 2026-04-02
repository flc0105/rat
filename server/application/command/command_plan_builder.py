import shlex


class CommandPlanBuilder:
    """
    命令执行计划构造器。

    职责：
    - 解析 acmd
    - 构造 alias / default / script / acmd 的远程执行参数
    - 不直接发送命令
    """

    ACMD_PREFIX = 'acmd'

    def __init__(self, alias_manager):
        self.alias_manager = alias_manager

    def is_argument_command(self, cmd: str) -> bool:
        parts = shlex.split(cmd or '')
        return bool(parts) and parts[0] == self.ACMD_PREFIX

    def parse_argument_command(self, cmd: str) -> dict:
        """
        解析 acmd 命令格式
        格式：
        acmd <command> [--arg1 value1] [--arg2 value2] [--flag] [--key=value]
        返回：
        {
            'name': 'msgbox',
            'args': {...},
            'raw': 'acmd ...'
        }
        """
        parts = shlex.split(cmd)

        if len(parts) < 2:
            raise ValueError('Usage: acmd <command> [--key value] [--flag]')

        if parts[0] != self.ACMD_PREFIX:
            raise ValueError('Invalid acmd format')

        command_name = (parts[1] or '').strip()
        if not command_name:
            raise ValueError('Missing acmd command name')

        args_dict = {}
        positional_args = []
        index = 2

        while index < len(parts):
            token = parts[index]

            if token == '--':
                positional_args.extend(parts[index + 1:])
                break

            if token.startswith('--'):
                option_text = token[2:]
                if not option_text:
                    raise ValueError('Empty option name is not allowed')

                if '=' in option_text:
                    key, value = option_text.split('=', 1)
                    key = key.strip()
                    if not key:
                        raise ValueError('Empty option name is not allowed')
                    args_dict[key] = value
                    index += 1
                    continue

                key = option_text.strip()
                if not key:
                    raise ValueError('Empty option name is not allowed')

                if index + 1 < len(parts) and not parts[index + 1].startswith('--'):
                    args_dict[key] = parts[index + 1]
                    index += 2
                    continue

                args_dict[key] = True
                index += 1
                continue

            positional_args.append(token)
            index += 1

        if positional_args:
            args_dict['_args'] = positional_args

        return {
            'name': command_name,
            'args': args_dict,
            'raw': cmd,
        }

    def build_alias_plan(self, name: str, arg: str) -> dict | None:
        alias_cmd = self.alias_manager.aliases.get(name)
        if not alias_cmd:
            return None

        expanded_cmd = self.alias_manager.get_alias_command(name, arg)
        return {
            'kind': 'remote_command',
            'command': expanded_cmd,
            'command_type': 'command',
            'extra': None,
        }

    def build_default_plan(self, raw_command: str) -> dict:
        return {
            'kind': 'remote_command',
            'command': raw_command,
            'command_type': 'command',
            'extra': None,
        }

    def build_argument_command_plan(self, raw_command: str) -> dict:
        payload = self.parse_argument_command(raw_command)
        return {
            'kind': 'remote_command',
            'command': raw_command,
            'command_type': 'acmd',
            'extra': payload,
        }

    def build_script_plan(self, script_text: str, script_args_extra) -> dict:
        return {
            'kind': 'remote_command',
            'command': script_text,
            'command_type': 'script',
            'extra': script_args_extra,
        }








