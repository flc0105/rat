import inspect
from dataclasses import dataclass, field
from typing import Any, Callable


class ArgumentCommandValidationError(ValueError):
    """
    acmd 参数校验异常
    """
    pass


@dataclass
class ArgumentOptionSpec:
    """
    单个 acmd 参数定义
    """
    name: str
    option_type: str = 'str'
    required: bool = False
    default: Any = None
    allow_empty: bool = True
    help_text: str = ''
    alias: str = ''
    positional_index: int | None = None

    @property
    def is_flag(self) -> bool:
        return self.option_type == 'flag'

    @property
    def is_positional(self) -> bool:
        return self.positional_index is not None


@dataclass
class ArgumentCommandSpec:
    """
    单个 acmd 命令定义
    """
    name: str
    description: str = ''
    options: list[ArgumentOptionSpec] = field(default_factory=list)

    def get_option_map(self) -> dict[str, ArgumentOptionSpec]:
        return {item.name: item for item in self.options}

    def get_option_alias_map(self) -> dict[str, ArgumentOptionSpec]:
        alias_map = {}
        option_map = self.get_option_map()

        for item in self.options:
            alias = str(item.alias or '').strip()
            if not alias:
                continue
            if len(alias) != 1 or alias.startswith('-'):
                raise ArgumentCommandValidationError(
                    f'Invalid alias for --{item.name}: alias must be a single character without dash'
                )
            if alias in option_map:
                raise ArgumentCommandValidationError(
                    f'Invalid alias for --{item.name}: -{alias} conflicts with option --{alias}'
                )
            if alias in alias_map:
                exists = alias_map[alias].name
                raise ArgumentCommandValidationError(
                    f'Duplicate alias -{alias} for --{exists} and --{item.name}'
                )
            alias_map[alias] = item

        return alias_map


def argument_command(name: str, spec: ArgumentCommandSpec | None = None):
    """
    标记一个 acmd 实验命令处理方法
    """
    def decorator(func):
        func.argument_command_name = name
        func.argument_command_spec = spec
        return func
    return decorator


class ArgumentCommandHelpBuilder:
    """
    acmd 帮助文本构造器
    """

    TYPE_LABELS = {
        'str': 'string',
        'int': 'int',
        'float': 'float',
        'bool': 'bool',
        'flag': 'flag',
    }

    def build(self, spec: ArgumentCommandSpec) -> str:
        lines = [self._build_usage_line(spec)]

        if spec.description:
            lines.append('')
            lines.append(spec.description)

        option_map = spec.get_option_map()
        if option_map:
            lines.append('')
            lines.append('Options:')

            for option in option_map.values():
                type_label = self.TYPE_LABELS.get(option.option_type, option.option_type)
                required_label = 'required' if option.required else 'optional'
                default_label = ''
                positional_label = ''

                if option.default not in (None, '') and option.option_type != 'flag':
                    default_label = f' default={option.default}'

                option_usage = self._build_option_help_usage(option)
                if option.option_type != 'flag' and option.is_positional:
                    positional_label = f' positional[{option.positional_index}]'

                lines.append(
                    f'  {option_usage:<22} {type_label:<7} {required_label:<8} '
                    f'{option.help_text}{default_label}{positional_label}'
                )

        return '\n'.join(lines).rstrip()

    def build_command_list(self, command_entries: list[dict]) -> str:
        """
        构造 acmd 命令列表帮助
        """
        lines = ['acmd help']

        if not command_entries:
            lines.append('')
            lines.append('No acmd commands registered')
            return '\n'.join(lines)

        lines.append('')
        lines.append('Registered acmd commands:')

        name_width = max(len(item.get('name', '')) for item in command_entries)
        name_width = max(name_width, 4)

        for item in command_entries:
            command_name = item.get('name', '')
            description = item.get('description') or 'No description'
            lines.append(f'  {command_name:<{name_width}}  {description}')

        lines.append('')
        lines.append('Use "acmd help <command>" to show command details')
        return '\n'.join(lines).rstrip()

    def _build_usage_line(self, spec: ArgumentCommandSpec) -> str:
        parts = [f'acmd {spec.name}']

        positional_options = [
            option for option in spec.options
            if option.is_positional and option.option_type != 'flag'
        ]
        positional_options.sort(key=lambda item: item.positional_index)

        for option in positional_options:
            token = f'<{option.name}>'
            if option.required:
                parts.append(token)
            else:
                parts.append(f'[{token}]')

        for option in spec.options:
            if option.is_positional and option.option_type != 'flag':
                continue

            option_token = self._build_option_usage_token(option)
            if option.option_type == 'flag':
                parts.append(f'[{option_token}]')
            elif option.required:
                parts.append(f'[{option_token} <value>]')
            else:
                parts.append(f'[{option_token} <value>]')

        return ' '.join(parts)

    def _build_option_usage_token(self, option: ArgumentOptionSpec) -> str:
        long_token = f'--{option.name}'
        alias = str(option.alias or '').strip()
        if alias:
            return f'-{alias}|{long_token}'
        return long_token

    def _build_option_help_usage(self, option: ArgumentOptionSpec) -> str:
        option_token = self._build_option_usage_token(option).replace('|', ', ')
        if option.option_type == 'flag':
            return option_token
        return f'{option_token} <value>'


class ArgumentCommandValidator:
    """
    acmd 参数归一化与校验器
    """

    def normalize(self, spec: ArgumentCommandSpec, raw_args: dict | None) -> dict:
        if raw_args is None:
            raw_args = {}

        if not isinstance(raw_args, dict):
            raise ArgumentCommandValidationError('Invalid acmd args payload')

        raw_args = self.normalize_arg_keys(spec, raw_args)
        option_map = spec.get_option_map()
        normalized = {}

        self._validate_unknown_options(option_map, raw_args)

        positional_args = raw_args.get('_args') or []
        if positional_args and not isinstance(positional_args, list):
            raise ArgumentCommandValidationError('Invalid positional args payload')

        for option_name, option_spec in option_map.items():
            has_value = option_name in raw_args
            raw_value = raw_args.get(option_name)

            if not has_value and option_spec.is_positional:
                positional_index = option_spec.positional_index
                if positional_index is not None and positional_index < len(positional_args):
                    raw_value = positional_args[positional_index]
                    has_value = True

            if not has_value:
                if option_spec.required and option_spec.default is None:
                    raise ArgumentCommandValidationError(
                        f'Missing required option: --{option_name}'
                    )
                normalized[option_name] = option_spec.default
                continue

            normalized_value = self._convert_value(option_spec, raw_value)

            if option_spec.option_type == 'str' and not option_spec.allow_empty:
                if str(normalized_value).strip() == '':
                    raise ArgumentCommandValidationError(
                        f'Option "--{option_name}" cannot be empty'
                    )

            normalized[option_name] = normalized_value

        if '_args' in raw_args:
            normalized['_args'] = positional_args

        return normalized

    def normalize_arg_keys(self, spec: ArgumentCommandSpec, raw_args: dict | None) -> dict:
        if raw_args is None:
            raw_args = {}

        if not isinstance(raw_args, dict):
            raise ArgumentCommandValidationError('Invalid acmd args payload')

        option_map = spec.get_option_map()
        alias_map = spec.get_option_alias_map()
        raw_args = self._normalize_alias_args(option_map, alias_map, raw_args)
        return self._normalize_inline_args(option_map, alias_map, raw_args)

    def _normalize_alias_args(
        self,
        option_map: dict[str, ArgumentOptionSpec],
        alias_map: dict[str, ArgumentOptionSpec],
        raw_args: dict,
    ) -> dict:
        normalized_args = {}
        source_keys = {}

        for key, value in raw_args.items():
            target_key = self._resolve_payload_option_key(option_map, alias_map, key)

            # 同时传入长名和短名时，dict 无法表达顺序，直接拒绝避免隐式覆盖。
            if target_key in normalized_args:
                self._raise_duplicate_option(target_key, source_keys.get(target_key, ''), key)

            normalized_args[target_key] = value
            source_keys[target_key] = key

        return normalized_args

    def _normalize_inline_args(
        self,
        option_map: dict[str, ArgumentOptionSpec],
        alias_map: dict[str, ArgumentOptionSpec],
        raw_args: dict,
    ) -> dict:
        positional_args = raw_args.get('_args') or []
        if not positional_args:
            return raw_args

        if not isinstance(positional_args, list):
            raise ArgumentCommandValidationError('Invalid positional args payload')

        normalized_args = {}
        source_keys = {}

        for key, value in raw_args.items():
            if key == '_args':
                continue
            normalized_args[key] = value
            source_keys[key] = key

        clean_positional_args = []
        index = 0

        while index < len(positional_args):
            item = positional_args[index]
            token = str(item)
            option_name, inline_value, has_inline_value = self._parse_inline_option_token(
                option_map,
                alias_map,
                token,
            )

            if option_name is None:
                clean_positional_args.append(item)
                index += 1
                continue

            option_spec = option_map[option_name]

            if option_spec.option_type == 'flag':
                option_value = inline_value if has_inline_value else True
                self._put_normalized_option(normalized_args, source_keys, option_name, option_value, token)
                index += 1
                continue

            if has_inline_value:
                option_value = inline_value
                index += 1
            else:
                if index + 1 >= len(positional_args):
                    raise ArgumentCommandValidationError(f'Option "--{option_name}" requires a value')
                option_value = positional_args[index + 1]
                index += 2

            self._put_normalized_option(normalized_args, source_keys, option_name, option_value, token)

        normalized_args['_args'] = clean_positional_args
        return normalized_args

    def _resolve_payload_option_key(
        self,
        option_map: dict[str, ArgumentOptionSpec],
        alias_map: dict[str, ArgumentOptionSpec],
        key: str,
    ) -> str:
        key_text = str(key or '').strip()
        if key_text.startswith('_'):
            return key

        option_key = self._strip_option_prefix(key_text)
        if option_key in option_map:
            return option_key
        if option_key in alias_map:
            return alias_map[option_key].name
        return key

    def _parse_inline_option_token(
        self,
        option_map: dict[str, ArgumentOptionSpec],
        alias_map: dict[str, ArgumentOptionSpec],
        token: str,
    ) -> tuple[str | None, Any, bool]:
        if token == '--':
            return None, None, False
        if not token.startswith('-') or self._looks_like_negative_number(token):
            return None, None, False

        if token.startswith('--'):
            option_key, inline_value, has_inline_value = self._split_inline_option_token(token[2:])
        else:
            option_key, inline_value, has_inline_value = self._split_inline_option_token(token[1:])

        if option_key in option_map:
            return option_key, inline_value, has_inline_value
        if option_key in alias_map:
            return alias_map[option_key].name, inline_value, has_inline_value

        raise ArgumentCommandValidationError(f'Unknown option: {self._format_option_key(token)}')

    def _split_inline_option_token(self, option_text: str) -> tuple[str, str, bool]:
        if '=' not in option_text:
            return option_text, '', False

        option_key, inline_value = option_text.split('=', 1)
        return option_key, inline_value, True

    def _strip_option_prefix(self, key: str) -> str:
        if key.startswith('--'):
            return key[2:]
        if key.startswith('-'):
            return key[1:]
        return key

    def _looks_like_negative_number(self, value: str) -> bool:
        try:
            float(value)
            return value.startswith('-') and len(value) > 1
        except Exception:
            return False

    def _put_normalized_option(
        self,
        normalized_args: dict,
        source_keys: dict,
        target_key: str,
        value: Any,
        source_key: str,
    ):
        if target_key in normalized_args:
            self._raise_duplicate_option(target_key, source_keys.get(target_key, ''), source_key)

        normalized_args[target_key] = value
        source_keys[target_key] = source_key

    def _raise_duplicate_option(
        self,
        target_key: str,
        existing_key: str,
        incoming_key: str,
    ):
        if existing_key == incoming_key:
            raise ArgumentCommandValidationError(
                f'Duplicate option: {self._format_option_key(existing_key)}'
            )

        raise ArgumentCommandValidationError(
            f'Duplicate option: {self._format_option_key(existing_key)} and '
            f'{self._format_option_key(incoming_key)} for --{target_key}'
        )

    def _validate_unknown_options(self, option_map: dict[str, ArgumentOptionSpec], raw_args: dict):
        for key in raw_args:
            if key.startswith('_'):
                continue
            if key not in option_map:
                raise ArgumentCommandValidationError(
                    f'Unknown option: {self._format_option_key(key)}'
                )

    def _format_option_key(self, key: str) -> str:
        text = str(key or '')
        if text.startswith('-'):
            return text
        if len(text) == 1:
            return f'-{text}'
        return f'--{text}'

    def _convert_value(self, option_spec: ArgumentOptionSpec, raw_value: Any):
        option_name = option_spec.name

        if option_spec.option_type == 'flag':
            return self._convert_flag_value(option_name, raw_value)

        if raw_value is True:
            raise ArgumentCommandValidationError(f'Option "--{option_name}" requires a value')

        if option_spec.option_type == 'str':
            return str(raw_value)

        if option_spec.option_type == 'int':
            try:
                return int(str(raw_value).strip())
            except Exception:
                raise ArgumentCommandValidationError(f'Option "--{option_name}" must be an integer')

        if option_spec.option_type == 'float':
            try:
                return float(str(raw_value).strip())
            except Exception:
                raise ArgumentCommandValidationError(f'Option "--{option_name}" must be a number')

        if option_spec.option_type == 'bool':
            return self._convert_bool_value(option_name, raw_value)

        return raw_value

    def _convert_flag_value(self, option_name: str, raw_value: Any) -> bool:
        if raw_value is True:
            return True

        if isinstance(raw_value, str):
            text = raw_value.strip().lower()
            if text in ('1', 'true', 'yes', 'on'):
                return True
            if text in ('0', 'false', 'no', 'off'):
                return False

        raise ArgumentCommandValidationError(f'Invalid flag value for --{option_name}')

    def _convert_bool_value(self, option_name: str, raw_value: Any) -> bool:
        if isinstance(raw_value, bool):
            return raw_value

        text = str(raw_value).strip().lower()
        if text in ('1', 'true', 'yes', 'on'):
            return True
        if text in ('0', 'false', 'no', 'off'):
            return False

        raise ArgumentCommandValidationError(f'Option "--{option_name}" must be true/false')


class ArgumentCommandRegistry:
    """
    acmd 实验命令注册表。

    职责：
    - 扫描命令对象上的实验命令处理器
    - 管理 handler + spec
    - 统一 help / 参数校验 / 执行分发
    - 输出 acmd 自动补全候选
    """

    HELP_OPTION_NAME = 'help'
    HELP_COMMAND_NAME = 'help'

    def __init__(self, commands):
        self.commands = commands
        self.help_builder = ArgumentCommandHelpBuilder()
        self.validator = ArgumentCommandValidator()
        self._entries = self._collect_entries()

    def _collect_entries(self) -> dict:
        """
        扫描并收集所有已注册的实验命令处理器
        """
        entries = {}

        for _, method in inspect.getmembers(
            self.commands,
            lambda x: inspect.ismethod(x) or inspect.isfunction(x)
        ):
            command_name = getattr(method, 'argument_command_name', '')
            if not command_name:
                continue

            spec = getattr(method, 'argument_command_spec', None)
            entries[command_name] = {
                'handler': method,
                'spec': spec,
            }

        return entries

    def has_command(self, name: str) -> bool:
        """
        判断是否存在指定实验命令
        """
        return name in self._entries

    def list_command_entries(self) -> list[dict]:
        """
        返回所有已注册 acmd 命令及其简短帮助信息
        """
        result = []

        for command_name, entry in self._entries.items():
            spec = entry.get('spec')
            description = ''

            if spec is not None:
                description = (spec.description or '').strip()

            result.append({
                'name': command_name,
                'description': description or 'No description',
            })

        result.sort(key=lambda item: item['name'])
        return result

    def get_manifest_payload(self) -> list[dict]:
        """
        生成 acmd 自动补全清单，供 client command_manifest 上报给 server/web。
        """
        payload = [
            {
                'name': 'acmd',
                'template': 'acmd help',
                'help': 'List all registered structured commands',
                'group': 'acmd',
                'suggest': True,
                'source': 'client',
            }
        ]

        for item in self.list_command_entries():
            command_name = item.get('name', '').strip()
            description = item.get('description') or 'No description'
            if not command_name:
                continue

            payload.append({
                'name': f'acmd {command_name}',
                'template': f'acmd {command_name}',
                'help': description,
                'group': 'acmd',
                'suggest': True,
                'source': 'client',
            })
            payload.append({
                'name': 'acmd',
                'template': f'acmd help {command_name}',
                'help': f'Show help for acmd command: {command_name}',
                'group': 'acmd',
                'suggest': False,
                'source': 'client',
            })

        return payload

    def execute(self, payload: dict):
        """
        执行实验命令
        payload 结构：
        {
            'name': 'msgbox',
            'args': {'title': 'aaa', 'text': 'bbb'},
            'raw': 'acmd msgbox --title aaa --text bbb'
        }
        """
        if not isinstance(payload, dict):
            return 0, 'Invalid acmd payload'

        command_name = (payload.get('name') or '').strip()
        raw_args = payload.get('args') or {}

        if not command_name:
            return 0, 'Missing acmd command name'

        if not isinstance(raw_args, dict):
            return 0, 'Invalid acmd args payload'

        if command_name == self.HELP_COMMAND_NAME:
            return self._execute_help_command(raw_args)

        entry = self._entries.get(command_name)
        if entry is None:
            return 0, f'acmd command not supported on this platform: {command_name}'

        handler = entry.get('handler')
        spec = entry.get('spec')

        try:
            if spec is not None:
                raw_args_for_help = self.validator.normalize_arg_keys(spec, raw_args)
                normalized_help_flag = self._normalize_help_flag(
                    raw_args_for_help.get(self.HELP_OPTION_NAME, False)
                )
                if normalized_help_flag:
                    return 1, self.help_builder.build(spec)

                normalized_args = self.validator.normalize(spec, raw_args)
            else:
                normalized_args = raw_args

            return self._invoke_handler(handler, normalized_args, payload)
        except ArgumentCommandValidationError as e:
            return 0, str(e)
        except Exception as e:
            return 0, f'acmd execution failed: {e}'

    def _execute_help_command(self, raw_args: dict) -> tuple[int, str]:
        """
        执行 acmd help
        支持：
        - acmd help
        - acmd help <command>
        """
        positional_args = raw_args.get('_args') or []
        if not isinstance(positional_args, list):
            return 0, 'Invalid acmd help args'

        if not positional_args:
            return 1, self.help_builder.build_command_list(self.list_command_entries())

        target_command_name = str(positional_args[0] or '').strip()
        if not target_command_name:
            return 0, 'Usage: acmd help [command]'

        entry = self._entries.get(target_command_name)
        if entry is None:
            return 0, f'acmd command not found: {target_command_name}'

        spec = entry.get('spec')
        if spec is None:
            return 0, f'acmd help is not available for: {target_command_name}'

        return 1, self.help_builder.build(spec)

    def _normalize_help_flag(self, value: Any) -> bool:
        if value is True:
            return True

        if isinstance(value, str):
            text = value.strip().lower()
            if text in ('1', 'true', 'yes', 'on'):
                return True
            if text in ('0', 'false', 'no', 'off', ''):
                return False

        return False

    def _invoke_handler(self, handler: Callable, args_dict: dict, payload: dict):
        parameters_count = len(inspect.signature(handler).parameters)

        if parameters_count >= 2:
            return handler(args_dict, payload)

        return handler(args_dict)