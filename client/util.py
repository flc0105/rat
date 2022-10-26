def format_dict(d):
    return '\n'.join(f'{key:15}{value}' for key, value in d.items())


def format_dict_with_index(d):
    return '\n'.join(f'{index:<5}{value[0]:15}{value[1]}' for index, value in enumerate(d.items()))


def wrap_path(path):
    return f'"{path}"' if ' ' in path else path
