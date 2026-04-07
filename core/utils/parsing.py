import argparse
import shlex
from typing import Iterable, List, Sequence, Tuple


class SafeArgumentParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__(add_help=False)
        self.error_message = None

    def error(self, message):
        self.error_message = message

    def parse_args(self, *args, **kwargs):
        namespace = super().parse_args(*args, **kwargs)
        if self.error_message:
            raise ValueError(self.error_message)
        return namespace


class CommandParser:
    @staticmethod
    def parse_command(command: str) -> Tuple[str, str]:
        normalized = command.replace('\\', '/').strip()
        if not normalized:
            return '', ''

        parts = shlex.split(normalized)
        if not parts:
            return '', ''

        command_name = parts[0]
        command_arg = normalized[len(command_name):].strip()
        return command_name, command_arg


def parse(cmd: str) -> Tuple[str, str]:
    return CommandParser.parse_command(cmd)


def parse_args(options: Sequence[str], arg_split: Sequence[str]) -> dict:
    parser = SafeArgumentParser()
    for option in options:
        parser.add_argument(f'--{option}', f'-{option[0]}', type=str, nargs='*', required=True)

    arg_dict = vars(parser.parse_args(arg_split))
    for option, value in arg_dict.items():
        if not value:
            raise ValueError(f'Null value not accepted: {option}')
        arg_dict[option] = ' '.join(value)
    return arg_dict


def parse_kwargs(kwargs: Sequence[Tuple[Sequence[str], dict]], arg_split: Sequence[str]) -> dict:
    parser = SafeArgumentParser()
    for kwarg in kwargs:
        parser.add_argument(*kwarg[0], **kwarg[1])

    arg_dict = vars(parser.parse_args(arg_split))
    for key, value in arg_dict.items():
        if isinstance(value, list):
            arg_dict[key] = ' '.join(value)
    return arg_dict


def scan_args(arg_split: Sequence[str]) -> dict:
    parser = SafeArgumentParser()
    options = [item for item in arg_split if item.startswith('--')]

    for option in options:
        parser.add_argument(option, nargs='*')

    arg_dict = vars(parser.parse_args(arg_split))
    for option, value in arg_dict.items():
        joined_value = ' '.join(value)
        arg_dict[option] = _coerce_scan_arg_value(joined_value)
    return arg_dict


# add exec kwargs boolean解析 2026-04-07 00:00
def _coerce_scan_arg_value(value):
    if not isinstance(value, str):
        return value

    normalized = value.strip()
    lowered = normalized.lower()

    if lowered == 'true':
        return True

    if lowered == 'false':
        return False

    return value