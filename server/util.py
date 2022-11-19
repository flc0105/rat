import glob
import json
import os
import re
import shlex
import threading
import traceback
import uuid

from common.util import Colors, format_dict, scan_args, parse


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
    readline = None
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
    print(f'{Colors.DARK_YELLOW}[{bar}] {percents} % {Colors.END}', end='\r')
    if count == total:
        print()


class Alias:
    list = {}
    config = 'server/alias.json'

    @staticmethod
    def send(conn, cmd):
        cmd_name, cmd_arg = parse(cmd)
        alias = Alias.list.get(cmd_name)
        regex = '<.*?>'
        args = shlex.split(cmd_arg)
        argc = len(re.findall(regex, alias))
        if argc > 0:
            if argc != len(args):
                print(f'[-] {cmd_name}: requires {argc} argument{"s" if argc > 1 else ""} ({len(args)} provided)')
                return
            for cmd_arg in args:
                alias = re.sub(regex, cmd_arg, alias, count=1)
        else:
            if len(args) != 0:
                print(f'[-] {cmd_name}: takes no argument')
                return
        print('[+] Sending command: {}'.format(alias))
        return conn.send_command(alias)

    @staticmethod
    def read():
        if os.path.isfile(Alias.config):
            with open(Alias.config, 'r') as f:
                try:
                    Alias.list = json.load(f)
                except json.decoder.JSONDecodeError:
                    print('[-] Error loading configuration: {}'.format(Alias.config))

    @staticmethod
    def write():
        with open(Alias.config, 'w') as f:
            f.write(json.dumps(Alias.list, sort_keys=True, indent=2))


class Command:

    @staticmethod
    def lcd(arg, conn):
        cd(arg)

    @staticmethod
    def upload(arg, conn):
        if os.path.isfile(arg):
            command_id = str(uuid.uuid4())
            threading.Thread(target=conn.send_file, args=(arg, command_id,), daemon=True).start()
            return command_id
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
        command_id = str(uuid.uuid4())
        threading.Thread(target=conn.send_file, args=(script_name, command_id, 'script', scan_args(arg[1:])),
                         daemon=True).start()
        return command_id

    @staticmethod
    def alias(arg, conn):
        if not arg:
            print(format_dict(Alias.list))
            return
        equal_mark_index = arg.find('=')
        if equal_mark_index == -1:
            print('[-] Syntax error')
            return
        alias = arg[0:equal_mark_index].strip()
        command = arg[equal_mark_index + 1:].strip()
        if not all([alias, command]):
            print('[-] Null value not accepted')
            return
        Alias.list[alias] = command
        Alias.write()
        print(f'[+] Alias set: {alias} -> {command}')

    @staticmethod
    def unalias(arg, conn):
        if not arg:
            print('[-] Syntax error')
            return
        if arg not in Alias.list:
            print(f'[-] Alias does not exist: {arg}')
            return
        del Alias.list[arg]
        Alias.write()
        print(f'[+] Alias unset: {arg}')


Alias.read()
internal_commands = get_internal_commands()
