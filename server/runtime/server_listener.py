import json
import socket
import threading
import time

from core.utils.logger import logger
from server.connection.transport.client_transport import ClientTransport


class ServerListener:
    def __init__(self, server):
        self.server = server

    def _bind_server_socket(self):
        """
        绑定并启动监听
        """
        # add 拆分服务端监听器绑定 2026-04-08
        self.server.socket.bind(self.server.address)
        logger.info('Listening on port {}'.format(self.server.address[1]))

    def _receive_client_info(self, raw_sock, addr):
        """
        接收客户端初始信息
        """
        # add 拆分服务端监听器握手接收 2026-04-08
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
        # add 拆分服务端监听器连接信息构造 2026-04-08
        return {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}

    def _register_connection(self, transport: ClientTransport, addr, info: dict):
        # add 拆分服务端监听器连接注册 2026-04-08
        session = self.server.web_service.connection_api.create_web_connection(transport, addr, info)
        self.server.connections.add(session)
        logger.info('Connection has been established: {}'.format(addr))
        self.server.web_service.connection_api.handle_connection_registered(session)
        return session

    def _accept_connection(self):
        """
        接受一个新连接并完成初始化
        """
        # add 拆分服务端监听器接受连接 2026-04-08
        raw_sock, addr = self.server.socket.accept()

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
        # add 拆分服务端监听器接收线程启动 2026-04-08
        threading.Thread(
            target=self.connection_handler,
            args=(session,),
            daemon=True
        ).start()

    def _notify_connection_closed(self, session):
        """
        通知等待中的主线程：该连接已关闭
        """
        # add 拆分服务端监听器连接关闭通知 2026-04-08
        session.runtime.message_queue.put(0, None, 1)

    def _remove_connection(self, session):
        """
        从连接管理器中移除连接
        """
        # add 拆分服务端监听器连接移除 2026-04-08
        self.server.connections.remove(session)

    def _handle_connection_closed(self, session):
        """
        处理连接关闭后的清理逻辑
        """
        # add 拆分服务端监听器连接关闭清理 2026-04-08
        logger.error(f'Connection closed: {session.address}')
        self.server.web_service.connection_api.handle_connection_closed(session)
        self._notify_connection_closed(session)
        self._remove_connection(session)

    def _handle_connection_receive_error(self, session):
        """
        处理接收线程中的非致命异常
        """
        # add 拆分服务端监听器接收异常处理 2026-04-08
        logger.error(f'Error receiving from {session.address}', exc_info=True)
        time.sleep(1)

    def connection_handler(self, session):
        """
        处理接收的子线程
        """
        # add 拆分服务端监听器会话接收循环 2026-04-08
        while 1:
            try:
                session.recv_message()
            except socket.error:
                self._handle_connection_closed(session)
                break
            except Exception:
                self._handle_connection_receive_error(session)

    def serve(self):
        """
        接受新连接的线程
        """
        # add 拆分服务端监听器主循环 2026-04-08
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