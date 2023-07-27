import os
import re
import traceback

from common.util import Colors


def completer(text, state):
    """
    自动补全函数
    :param text: 输入的文本
    :param state: 状态
    :return: 补全选项
    """
    options = [cmd for cmd in get_commands() if cmd.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None


try:
    if os.name == 'posix':
        import readline

        readline.parse_and_bind('tab: complete')
        readline.set_completer(completer)
except ImportError:
    readline = None
    traceback.print_exc()


def get_commands():
    """
    获取所有命令列表
    :return: 命令列表
    """
    return ['cd', 'clear', 'exit', 'list', 'quit', 'select', 'kill']


def cd(path: str):
    """
    改变当前工作路径
    :param path: 目标路径
    :return: 当前工作路径
    """
    if os.path.exists(path):
        os.chdir(path)
    return os.getcwd()


def colored_input(text: str):
    """
    彩色输入
    :param text: 输入提示文本
    :return: 用户输入的内容
    """
    inp = input(Colors.RESET + text + Colors.BRIGHT_YELLOW)
    print(Colors.RESET, end='', flush=True)
    return inp


def print_error(text):
    """
     打印错误信息
     :param text: 错误信息
     """
    print(f'{Colors.BRIGHT_RED}{text}{Colors.RESET}')


def get_user_type(integrity: str):
    """
    获取用户类型
    :param integrity: 安全完整性级别
    :return: 用户类型
    """
    user_type = {
        'Medium': 'user',
        'High': 'admin',
        'System': 'system'
    }
    return user_type.get(integrity)


def write(status: int, result: str):
    """
    在控制台输出结果
    :param status: 0或者1
    :param result: 结果
    """
    if not status:
        result = Colors.BRIGHT_RED + result + Colors.RESET
    print(result)


def find_and_highlight_keywords(text, keyword):
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)

    def highlight(match):
        return f'{Colors.BRIGHT_RED}{match.group()}{Colors.RESET}'

    highlighted_lines = []
    for line in text.splitlines():
        if pattern.search(line):
            highlighted_line = pattern.sub(highlight, line)
            highlighted_lines.append(highlighted_line)

    return '\n'.join(highlighted_lines)


def secure_filename(filename):
    # Windows 文件命名非法字符：\ / : * ? " < > |
    illegal_chars = r'[\\/:\*\?"<>|]'
    return re.sub(illegal_chars, '_', filename)


def replace_spaces(input_str, replacement='_'):
    return re.sub(r'\s+', replacement, input_str)


def calculate_time_interval(start_time, end_time):
    # 将时间戳转换为浮点数，以秒为单位
    start_time_sec = float(start_time)
    end_time_sec = float(end_time)

    # 计算间隔时间，单位为毫秒
    interval_ms = (end_time_sec - start_time_sec) * 1000
    return interval_ms
