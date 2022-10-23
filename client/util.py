import time


def get_time():
    return time.strftime('%Y%m%d-%H%M%S')


def format_dict(d):
    return '\n'.join(f'{key:15}{value}' for key, value in d.items())


def wrap_path(path):
    return f'"{path}"' if ' ' in path else path
