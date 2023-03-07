import os
import traceback

from common.util import Colors


def completer(text, state):
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
    return ['cd', 'clear', 'exit', 'list', 'quit', 'select', 'kill']


def cd(path: str):
    if os.path.exists(path):
        os.chdir(path)
    return os.getcwd()


def colored_input(text: str):
    inp = input(Colors.RESET + text + Colors.BRIGHT_YELLOW)
    print(Colors.RESET, end='', flush=True)
    return inp


def print_error(text):
    print(f'{Colors.BRIGHT_RED}{text}{Colors.RESET}')


def get_user_type(integrity: str):
    user_type = {
        'Medium': 'user',
        'High': 'admin',
        'System': 'system'
    }
    return user_type.get(integrity)
