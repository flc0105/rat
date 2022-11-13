import glob
import json
import os
import re
import shlex
import threading
import traceback

from common.util import Colors, format_dict, parse, scan_args


class Context:
    current_connection = None
    last_command_id = None
    eof_event = threading.Event()
    eof_event.set()
    state = 'local'
    remote_commands = []


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


def get_commands():
    if Context.state == 'local':
        return ['cd', 'clear', 'exit', 'list', 'quit', 'select']
    else:
        return ['exit', 'kill', 'reset', 'quit'] + Context.remote_commands + list(internal_commands.keys())


def cd(path: str):
    if os.path.exists(path):
        os.chdir(path)
    print(os.getcwd())


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


def get_internal_commands():
    return {name: getattr(Command, name) for name, func in vars(Command).items() if callable(getattr(Command, name))}


def update_progress(count, total):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    print('%s[%s] %s%s%s' % (Colors.DARK_YELLOW, bar, percents, '%', Colors.END), end='\r')


def send_alias(conn, cmd):
    cmd_name, cmd_arg = parse(cmd)
    alias = AliasUtil.get(cmd_name)
    regex = '<.*?>'
    args = shlex.split(cmd_arg)
    argc = len(re.findall(regex, alias))
    if argc > 0:
        if argc == len(args):
            for cmd_arg in args:
                alias = re.sub(regex, cmd_arg, alias, count=1)
        else:
            raise Exception(f'{cmd_name}: requires {argc} argument{"s" if argc > 1 else ""} ({len(args)} provided)')
    else:
        if len(args) != 0:
            raise Exception(f'{cmd_name}: takes no argument')
    print('[+] Sending command: {}'.format(alias))
    return conn.send_command(alias)


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
        cd(arg)

    @staticmethod
    def upload(arg, conn):
        if os.path.isfile(arg):
            cmd_id = conn.send_file(arg)
            return cmd_id
        else:
            print('[-] File does not exist')

    @staticmethod
    def load(arg, conn):
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
        cmd_id = conn.send_file(script_name, type='script', args=scan_args(arg[1:]))
        return cmd_id

    @staticmethod
    def alias(arg, conn):
        if not arg:
            print(format_dict(AliasUtil.list(), width=20))
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
        if not arg:
            print('syntax error')
            return
        AliasUtil.remove(arg)
        print('alias unset: {}'.format(arg))


AliasUtil.load()
internal_commands = get_internal_commands()
