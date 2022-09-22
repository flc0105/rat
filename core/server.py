import json
import socket

from entity.client import Client
from entity.ratsocket import RATSocket
from util.notifier import notify


class Server:

    def __init__(self, address):
        # 服务端地址
        self.address = address
        # 服务端套接字
        self.socket = RATSocket()
        # 存储已连接客户端的数组
        self.connections = []

    # 等待连接
    def serve(self):
        print('[+] Listening on port {}'.format(self.address[1]))
        self.socket.serve(self.address, self.handler)

    # 接受连接后的回调函数
    def handler(self, conn, addr):
        # 设置5秒超时
        conn.settimeout(5)
        try:
            # 接收验证信息
            _, info = Client(conn, None, None).recv_result()
            info = json.loads(info)
            # 取消超时
            conn.settimeout(None)
            # 保存连接
            self.connections.append(Client(conn, addr, info))
            print('[+] Connection has been established: {}'.format(addr))
            # 上线提醒
            notify(info)
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
