import argparse
import logging
import os.path
import shlex
import sys
import time
from pathlib import Path


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


def get_readable_time():
    return time.strftime('%Y-%m-%d %H:%M:%S')


def get_output_stream(filename):
    f = open(filename, 'rb')
    return f


def get_input_stream(filename):
    # 如果文件存在重复，在文件名上加一个时间戳
    if os.path.exists(filename):
        path = Path(filename)
        filename = path.with_stem(f'{path.stem}_{int(time.time())}')
    f = open(filename, 'ab')
    f.truncate(0)
    return f


def format_dict(dict, width=15, index=False):
    if not index:
        return '\n'.join(f'{k:{width}}{v}' for k, v in dict.items())
    else:
        return '\n'.join(f'{i:<5}{k:{width}}{v}' for i, (k, v) in enumerate(dict.items()))


def parse(cmd):
    cmd = cmd.replace('\\', '/')
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


def parse_kwargs(kwargs, arg_split):
    parser = ArgumentParser()
    for kwarg in kwargs:
        parser.add_argument(*kwarg[0], **kwarg[1])
    arg_dict = vars(parser.parse_args(arg_split))
    if parser.message:
        raise Exception(parser.message)
    for key, value in arg_dict.items():
        if isinstance(value, list):
            arg_dict[key] = ' '.join(value)
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
        super().__init__(add_help=False)
        self.message = None

    def error(self, message):
        self.message = message

    def parse_args(self, *args, **kwargs):
        return super(ArgumentParser, self).parse_args(*args, **kwargs)


def draw_progress_bar(progress, total, bar_len=50):
    done = int(50 * progress / total)
    percent = round(100 * progress / total)
    bar = '=' * done
    spaces = '-' * (bar_len - done)
    sys.stdout.write(f'\r[{bar}{spaces}] {percent} %')
    sys.stdout.flush()
    if progress == total:
        sys.stdout.write('\n')


def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor
