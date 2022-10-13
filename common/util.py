import argparse
import logging

logging.basicConfig(
    format='[%(asctime)s] %(levelname)s: %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def parse(command: str) -> (str, str):
    """
    将命令拆分为命令名和参数
    """
    name = command.split()[0]
    arg = command[len(name) + 1:].strip()
    return name, arg


def parse_args(options: list, arg: str) -> dict:
    """
    解析命令参数
    """
    parser = ArgumentParser()
    for option in options:
        parser.add_argument(f'--{option}', f'-{option[0]}', type=str, nargs='*', required=True)
    args = vars(parser.parse_args(arg.split()))
    if parser.message:
        raise Exception(parser.message)
    for option in args:
        if not args[option]:
            raise Exception('Null value not accepted: {}'.format(option))
        args[option] = ' '.join(args[option])
    return args


def scan_args(arg: list) -> dict:
    """
    扫描参数字符串获得参数字典
    """
    parser = ArgumentParser()
    keys = [k for k in arg if k.startswith('--')]
    for k in keys:
        parser.add_argument(k, nargs='*')
    args = vars(parser.parse_args(arg))
    for option in args:
        args[option] = ' '.join(args[option])
    return args


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__()
        self.message = None

    def error(self, message):
        self.message = message

    def parse_args(self, *args, **kwargs):
        return super(ArgumentParser, self).parse_args(*args, **kwargs)