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



def print_table( headers, data):
    """
    通用表格打印方法
    :param headers: 表头列表，如 ['ID', 'Name', 'Age']
    :param data: 二维数据列表，每行对应一行的数据，如 [['1', 'Alice', '20'], ['2', 'Bob', '25']]
    """
    if not headers or not data:
        print("No data to display")
        return

    # 确保数据行数与列数匹配
    col_count = len(headers)
    data = [row for row in data if len(row) == col_count]
    if not data:
        print("Data format does not match headers")
        return

    # 计算每列最大宽度（考虑表头和数据）
    col_widths = [
        max(len(str(headers[i])), *(len(str(row[i])) for row in data))
        for i in range(col_count)
    ]

    # 构建格式字符串
    row_format = " | ".join([f"{{:<{w}}}" for w in col_widths])

    # 打印表头
    print("\n" + row_format.format(*headers))
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))  # 分隔线

    # 打印数据行
    for row in data:
        print(row_format.format(*row))

    print()  # 结尾空行


def parse_ratcmd(cmd_text):
    """
    解析ratcmd命令格式
    格式: ratcmd <command> [--arg1 value1] [--arg2 value2] [--flag]
    返回: (command_name, args_dict)
    """
    if not cmd_text.startswith('ratcmd '):
        raise ValueError("Not a ratcmd format")

    # 移除开头的'ratcmd '，然后按空格分割
    remaining = cmd_text[len('ratcmd '):].strip()
    parts = []

    # 手动解析，处理带引号的参数
    i = 0
    while i < len(remaining):
        if remaining[i] in ['"', "'"]:
            # 找到引号内的内容
            quote_char = remaining[i]
            end_quote = remaining.find(quote_char, i + 1)
            if end_quote == -1:
                # 没有结束引号，将剩余部分作为整个参数
                parts.append(remaining[i:])
                break
            parts.append(remaining[i + 1:end_quote])
            i = end_quote + 1
        elif remaining[i] == ' ':
            # 跳过空格
            i += 1
        else:
            # 找到下一个空格
            next_space = remaining.find(' ', i)
            if next_space == -1:
                parts.append(remaining[i:])
                break
            parts.append(remaining[i:next_space])
            i = next_space + 1

    if not parts:
        raise ValueError("Invalid ratcmd format: missing command name")

    command_name = parts[0]
    args_dict = {}
    i = 1

    while i < len(parts):
        part = parts[i]
        if part.startswith('--'):
            key = part[2:]  # 移除 '--'
            # 检查下一个部分是否是值（不以--开头）
            if i + 1 < len(parts) and not parts[i + 1].startswith('--'):
                args_dict[key] = parts[i + 1]
                i += 2  # 跳过值
            else:
                args_dict[key] = True  # 开关参数，设置为True
                i += 1
        else:
            # 对于没有--前缀的参数，作为位置参数处理
            args_dict[f'arg{len([k for k in args_dict if k.startswith("arg")]) + 1}'] = part
            i += 1

    return command_name, args_dict

    # while i < len(parts):
    #     part = parts[i]
    #     if part.startswith('--'):
    #         key = part[2:]  # 移除 '--'
    #         # 检查是否有对应的值
    #         if i + 1 < len(parts) and not parts[i + 1].startswith('--'):
    #             args_dict[key] = parts[i + 1]
    #             i += 2
    #         else:
    #             args_dict[key] = True  # 标志参数
    #             i += 1
    #     else:
    #         # 位置参数
    #         args_dict[f'arg{len([k for k in args_dict if k.startswith("arg")]) + 1}'] = part
    #         i += 1
    #
    # return command_name, args_dict


def validate_required_args(args_dict, required_args):
    """
    验证必需参数是否存在
    """
    missing = [arg for arg in required_args if arg not in args_dict]
    if missing:
        raise ValueError(f"Missing required arguments: {', '.join(missing)}")
    return True