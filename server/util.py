import glob
import json
import os
import re
import shlex
import threading
import time
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
    return os.getcwd()


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
                return 0, (0, f'{cmd_name}: requires {argc} argument{"s" if argc > 1 else ""} ({len(args)} provided)')
            for cmd_arg in args:
                alias = re.sub(regex, cmd_arg, alias, count=1)
        else:
            if len(args) != 0:
                return 0, (0, f'{cmd_name}: takes no argument')
        print('[+] Sending command: {}'.format(alias))
        return conn.send_command(alias), None

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
        return 0, (1, cd(arg))

    @staticmethod
    def upload(arg, conn):
        if os.path.isfile(arg):
            command_id = str(uuid.uuid4())
            threading.Thread(target=conn.send_file, args=(arg, command_id,), daemon=True).start()
            return command_id, None
        else:
            return 0, (0, 'File does not exist')

    @staticmethod
    def load(arg, conn):
        script_dir = 'server/script/'
        scripts = []
        if not arg:
            for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
                scripts.append(os.path.relpath(file, script_dir).replace('\\', '/'))
            return 0, (1, '\n'.join(scripts))
        arg = shlex.split(arg)
        script_name = os.path.abspath(os.path.join(script_dir, arg[0]))
        if not os.path.isfile(script_name):
            return 0, (0, f'File does not exist: {script_name}')
        print(f'[+] Sending script: {script_name}')
        command_id = str(uuid.uuid4())
        threading.Thread(target=conn.send_file, args=(script_name, command_id, 'script', scan_args(arg[1:])),
                         daemon=True).start()
        return command_id, None

    @staticmethod
    def alias(arg, conn):
        if not arg:
            return 0, (1, format_dict(Alias.list))
        equal_mark_index = arg.find('=')
        if equal_mark_index == -1:
            return 0, (0, 'Syntax error')
        alias = arg[0:equal_mark_index].strip()
        command = arg[equal_mark_index + 1:].strip()
        if not all([alias, command]):
            return 0, (0, 'Null value not accepted')
        Alias.list[alias] = command
        Alias.write()
        return 0, (1, f'Alias set: {alias} -> {command}')

    @staticmethod
    def unalias(arg, conn):
        if not arg:
            return 0, (0, 'Syntax error')
        if arg not in Alias.list:
            return 0, (0, f'Alias does not exist: {arg}')
        del Alias.list[arg]
        Alias.write()
        return 0, (1, f'Alias unset: {arg}')

    @staticmethod
    def history(arg, conn):
        if arg == '--result':
            return 0, (1, json.dumps(conn.result, ensure_ascii=False, indent=2))
        if arg == '--clear':
            conn.result.clear()
        command_list = []
        for cmd in conn.result.keys():
            command_list.append(conn.result[cmd]['command'])
        return 0, (1, '\n'.join(command_list))

    @staticmethod
    def outfile(arg, conn):
        if not arg.strip():
            return 0, (0, 'No command specified')
        command_id = conn.send_command(arg)
        if command_id:
            conn.result[command_id] = {}
            conn.result[command_id]['command'] = arg
            Context.last_command_id = command_id
            Context.eof_event.clear()
        while 1:
            result = conn.result[command_id].get('result')
            if result:
                filename = 'cmd.txt'
                with open(filename, 'w') as f:
                    f.write(result[1])
                return 0, (1, f'Command result saved to: {os.path.abspath(filename)}')
            time.sleep(0.1)


Alias.read()
internal_commands = get_internal_commands()
