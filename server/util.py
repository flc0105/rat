import glob
import os
import shlex

import common.util
from common.util import colors


def cd(path: str):
    if os.path.exists(path):
        os.chdir(path)
    print(os.getcwd() + '\n')


def colored_input(text: str):
    inp = input(text + colors.BRIGHT_YELLOW)
    print(colors.RESET, end='', flush=True)
    return inp


def get_user_type(integrity: str):
    user_type = {
        'Medium': 'user',
        'High': 'admin',
        'System': 'system'
    }
    return user_type[integrity]


def get_funcs():
    return {name: func for name, func in vars(Command).items() if callable(func)}


def update_progress(count, total):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    print('%s[%s] %s%s%s' % (colors.DARK_YELLOW, bar, percents, '%', colors.END), end='\r')


class Command:

    @staticmethod
    def lcd(arg, conn):
        """ 切换本地目录 """
        cd(arg)
        return 0

    @staticmethod
    def upload(arg, conn):
        """ 上传文件 """
        if os.path.isfile(arg):
            conn.send_file(arg)
            return 1
        else:
            print('[-] File does not exist')
            return 0

    @staticmethod
    def load(arg, conn):
        """ 加载脚本 """
        script_dir = 'server/script/'
        if not arg:
            for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
                print(os.path.relpath(file, script_dir))
            return 0
        arg = shlex.split(arg)
        script_name = os.path.join(script_dir, arg[0])
        if not os.path.isfile(script_name):
            print('[-] File does not exist: {}'.format(os.path.abspath(script_name)))
            return 0
        conn.send_file(script_name, type='script', args=common.util.scan_args(arg[1:]))
        return 1
