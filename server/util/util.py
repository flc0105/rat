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
    # 生成正则表达式，使用单词边界确保只匹配整个单词
    # pattern = re.compile(r'\b(?:' + '|'.join(map(re.escape, keywords)) + r')\b')
    # pattern = re.compile(r'\b(?:' + '|'.join(map(re.escape, keywords)) + r')\b', re.IGNORECASE)
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    # 将匹配的关键字用 HTML 标签包裹来高亮显示
    def highlight(match):
        return f'{Colors.BRIGHT_RED}{match.group()}{Colors.RESET}'

    # 按行匹配关键字并高亮显示，只保留匹配的行
    highlighted_lines = []
    for line in text.splitlines():
        if pattern.search(line):
            highlighted_line = pattern.sub(highlight, line)
            highlighted_lines.append(highlighted_line)

    return '\n'.join(highlighted_lines)

def grep(cmd):
    grep_pattern = r'\s*\|\s*grep\s+(\w+)\s*$'
    match = re.search(grep_pattern, cmd)
    if match:
        keywords = match.group(1)
        cmd = re.sub(grep_pattern, '', cmd)
        func = self.process_command(cmd, conn, executor)
        result = []
        for i in func():
            if len(i) >= 2:
                result.append(i[1])
        text = '\n'.join(result)
        print(find_and_highlight_keywords(text, keywords))