import glob
import json
import os
import re
import shlex
import traceback

from common.util import colors, get_time, parse, scan_args


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
    traceback.print_exc()

global state
state = 'local'

global remote_commands
remote_commands = []

preset_local_commands = ['cd', 'quit', 'exit', 'list', 'select', 'clear']
preset_remote_commands = ['quit', 'exit', 'kill', 'reset']


def change_state(s):
    global state
    state = s


def get_commands():
    if state == 'local':
        return preset_local_commands
    else:
        return preset_remote_commands + remote_commands + list(get_internal_cmd().keys())


def get_remote_commands(conn):
    conn.send_command('_cmdlist')
    global remote_commands
    remote_commands = json.loads(conn.recv_result()[1])
    change_state('remote')


def cd(path: str):
    if os.path.exists(path):
        os.chdir(path)
    print(os.getcwd())


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
    return user_type.get(integrity)


def get_internal_cmd():
    return {name: getattr(Command, name) for name, func in vars(Command).items() if callable(getattr(Command, name))}


def update_progress(count, total):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    print('%s[%s] %s%s%s' % (colors.DARK_YELLOW, bar, percents, '%', colors.END), end='\r')


def send_alias(conn, cmd):
    # 分割别名和参数
    name, arg = parse(cmd)
    # 命令原型
    proto = AliasUtil.get(name)
    # 匹配参数
    regex = '<.*?>'
    # 分割别名参数
    args = shlex.split(arg)
    # 命令原型参数个数
    argc = len(re.findall(regex, proto))
    # 原型带参数
    if argc > 0:
        # 原型参数和别名参数一致
        if argc == len(args):
            for arg in args:
                proto = re.sub(regex, arg, proto, count=1)
        else:
            raise Exception(
                'command "{}" takes {} argument{} but {} were given'.format(name, argc, 's' if argc > 1 else '',
                                                                            len(args)))
    else:
        # 原型不带参数 别名带参数
        if len(args) != 0:
            raise Exception('command "{}" takes no argument'.format(name))

    print('[+] Sending command: {}'.format(proto))
    conn.send_command(proto)


class AliasUtil:
    aliases = {}
    config_path = 'server/alias.json'

    @staticmethod
    def list():
        return AliasUtil.aliases

    @staticmethod
    def get(alias):
        return AliasUtil.aliases[alias]

    @staticmethod
    def add(alias, command):
        AliasUtil.aliases[alias] = command
        AliasUtil.save()

    @staticmethod
    def remove(alias):
        if alias not in AliasUtil.aliases:
            raise Exception('alias does not exist: {}'.format(alias))
        del AliasUtil.aliases[alias]
        AliasUtil.save()

    @staticmethod
    def load():
        if os.path.isfile(AliasUtil.config_path):
            with open(AliasUtil.config_path, 'r') as f:
                try:
                    AliasUtil.aliases = json.load(f)
                except json.decoder.JSONDecodeError:
                    print('[-] Error loading configuration: {}'.format(AliasUtil.config_path))

    @staticmethod
    def save():
        with open(AliasUtil.config_path, 'w') as f:
            f.write(json.dumps(AliasUtil.aliases, sort_keys=True, indent=2))


class Command:

    @staticmethod
    def lcd(arg, conn):
        """ 切换本地目录 """
        cd(arg)

    @staticmethod
    def outfile(arg, conn):
        """ 保存命令输出到文件 """
        if not arg:
            return
        conn.send_command(arg)
        status, result = conn.recv_result()
        wd = conn.recv_result()
        if not result.strip():
            return
        filename = f'{get_time()}.txt'
        with open(filename, 'w') as f:
            f.write(result)
        print('Command output saved to: {}'.format(os.path.abspath(filename)))

    @staticmethod
    def upload(arg, conn):
        """ 上传文件 """
        if os.path.isfile(arg):
            conn.send_file(arg)
            return 1
        else:
            print('[-] File does not exist')

    @staticmethod
    def load(arg, conn):
        """ 加载脚本 """
        script_dir = 'server/script/'
        if not arg:
            for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
                print(os.path.relpath(file, script_dir).replace('\\', '/'))
            return
        arg = shlex.split(arg)
        script_name = os.path.abspath(os.path.join(script_dir, arg[0]))
        if not os.path.isfile(script_name):
            print('[-] File does not exist: {}'.format(script_name))
            return
        print('[+] Sending script: {}'.format(script_name))
        conn.send_file(script_name, type='script', args=scan_args(arg[1:]))
        return 1

    @staticmethod
    def alias(arg, conn):
        """ 设置命令别名 """
        if not arg:
            print('\n'.join(f'{k:15}{v}' for k, v in AliasUtil.list().items()))
            return
        equal_mark_index = arg.find('=')
        if equal_mark_index == -1:
            print('syntax error')
            return
        alias = arg[0:equal_mark_index].strip()
        command = arg[equal_mark_index + 1:].strip()
        if not all([alias, command]):
            print('null value not accepted')
            return
        AliasUtil.add(alias, command)
        print('alias set: {} -> {}'.format(alias, command))

    @staticmethod
    def unalias(arg, conn):
        """ 删除命令别名 """
        if not arg:
            print('syntax error')
            return
        AliasUtil.remove(arg)
        print('alias unset: {}'.format(arg))


AliasUtil.load()
internal_cmd = get_internal_cmd()
