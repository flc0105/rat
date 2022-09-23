import json
import socket

from entity.client import Client
from entity.ratsocket import RATSocket


class Server:

    def __init__(self, address):
        # 服务端地址
        self.address = address
        # 服务端套接字
        self.socket = RATSocket()
        # 存储已连接客户端的数组
        self.connections = []

    # 等待连接
    def serve(self, handler):
        print('[+] Listening on port {}'.format(self.address[1]))
        self.socket.serve(self.address, handler)

    # 接受连接
    def accept(self, conn, addr):
        # 设置5秒超时
        conn.settimeout(5)
        try:
            # 接收验证信息
            info = json.loads(Client(conn, None, None).recv_result()[1])
            # 取消超时
            conn.settimeout(None)
            # 保存连接
            self.connections.append(Client(conn, addr, info))
            print('[+] Connection has been established: {}'.format(addr))
            return info
        except:
            # 关闭连接
            conn.close()
            print('[-] Rejected connection: {}'.format(addr))

    # 移除无效连接
    def test_connections(self):
        for i, conn in reversed(list(enumerate(self.connections))):
            try:
                conn.send_command('null', 'null')
                conn.recv_result()
            except socket.error:
                del self.connections[i]
