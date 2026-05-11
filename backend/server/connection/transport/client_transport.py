from core.protocol.rchsocket import RCHSocket


class ClientTransport(RCHSocket):
    """
    客户端底层传输对象。
    仅保留普通消息收发。
    """

    def __init__(self, sock, address=None):
        super().__init__()
        self.socket = sock
        self.address = address









