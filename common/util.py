import argparse
import logging
import shlex
import time


class Colors:
    DARK_RED = '\033[0;31m'
    DARK_GREEN = '\033[0;32m'
    DARK_YELLOW = '\033[0;33m'
    DARK_BLUE = '\033[0;34m'
    BRIGHT_RED = '\033[0;91m'
    BRIGHT_GREEN = '\033[0;92m'
    BRIGHT_YELLOW = '\033[0;93m'
    BRIGHT_BLUE = '\033[0;94m'
    RESET = '\033[0;39m\033[0m'
    END = '\033[0m'


logging.basicConfig(
    format='[%(asctime)s] %(levelname)s: %(funcName)s -> %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def get_time():
    return time.strftime('%Y%m%d-%H%M%S')


def get_read_stream(filename):
    f = open(filename, 'rb')
    return f


def get_write_stream(filename):
    f = open(filename, 'ab')
    f.truncate(0)
    return f


def format_dict(dict, width=15, index=False):
    if not index:
        return '\n'.join(f'{k:{width}}{v}' for k, v in dict.items())
    else:
        return '\n'.join(f'{i:<5}{k:{width}}{v}' for i, (k, v) in enumerate(dict.items()))


def parse(cmd):
    cmd_name = shlex.split(cmd)[0]
    cmd_arg = cmd[len(cmd_name) + 1:].strip()
    return cmd_name, cmd_arg


def parse_args(options, arg_split):
    parser = ArgumentParser()
    for option in options:
        parser.add_argument(f'--{option}', f'-{option[0]}', type=str, nargs='*', required=True)
    arg_dict = vars(parser.parse_args(arg_split))
    if parser.message:
        raise Exception(parser.message)
    for option in arg_dict:
        if not arg_dict[option]:
            raise Exception('Null value not accepted: {}'.format(option))
        arg_dict[option] = ' '.join(arg_dict[option])
    return arg_dict


def scan_args(arg_split):
    parser = ArgumentParser()
    options = [x for x in arg_split if x.startswith('--')]
    for option in options:
        parser.add_argument(option, nargs='*')
    arg_dict = vars(parser.parse_args(arg_split))
    for option in arg_dict:
        arg_dict[option] = ' '.join(arg_dict[option])
    return arg_dict


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__()
        self.message = None

    def error(self, message):
        self.message = message

    def parse_args(self, *args, **kwargs):
        return super(ArgumentParser, self).parse_args(*args, **kwargs)
