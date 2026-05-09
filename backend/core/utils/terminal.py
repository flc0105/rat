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


def colorize(text: str, color: str) -> str:
    return f'{color}{text}{Colors.RESET}'


def print_error(text: str) -> None:
    print(colorize(text, Colors.BRIGHT_RED))


def write(status: int, result: str) -> None:
    if not status:
        print_error(result)
        return
    print(result)


def colored_input(prompt: str) -> str:
    user_input = input(Colors.RESET + prompt + Colors.BRIGHT_YELLOW)
    print(Colors.RESET, end='', flush=True)
    return user_input