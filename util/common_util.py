import argparse


def parse(command: str) -> (str, str):
    """
    将命令拆分为命令名和参数
    """
    name = command.split()[0]
    arg = command[len(name) + 1:].strip()
    return name, arg


def decode(bytes: bytes) -> str:
    """
    utf-8解码失败时尝试gbk
    """
    try:
        str = bytes.decode('utf-8')
    except:
        try:
            str = bytes.decode('gbk')
        except:
            pass
    return str


def parse_args(options: list, arg: str):
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
        yield ' '.join(args[option])


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__()
        self.message = None

    def error(self, message):
        self.message = message

    def parse_args(self, *args, **kwargs):
        return super(ArgumentParser, self).parse_args(*args, **kwargs)
