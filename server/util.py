import glob
import inspect
import os
import shlex
import sys

import common.util


def get_funcs():
    """ 获取函数列表 """
    funcs = {}
    for name, value in vars(sys.modules[__name__]).items():
        if name == inspect.stack()[0][3] or not callable(value):
            continue
        funcs[name] = value
    return funcs


def upload(arg, conn):
    """ 向客户端发送文件 """
    if os.path.isfile(arg):
        conn.send_file(arg)
        return 1
    else:
        print('[-] File does not exist')
        return 0


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
    conn.send_file(script_name, 'script', common.util.scan_args(arg[1:]))
    return 1
