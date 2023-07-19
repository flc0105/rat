import os
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
