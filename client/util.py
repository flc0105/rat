import os
import sys
import time


def get_time():
    return time.strftime('%Y%m%d-%H%M%S')


def get_executable_path():
    if not getattr(sys, 'frozen', False):
        return '"{}" "{}"'.format(sys.executable, os.path.abspath(' '.join(sys.argv)))
    else:
        return '"{}"'.format(os.path.realpath(sys.executable))


def get_appname_and_cmdline():
    if not getattr(sys, 'frozen', False):
        return r'c:\windows\system32\cmd.exe', '/c {} {}'.format(sys.executable, os.path.abspath(' '.join(sys.argv)))
    else:
        return os.path.realpath(sys.executable), None


def format_dict(dict):
    return '\n'.join(f'{key:15}{value}' for key, value in dict.items())
