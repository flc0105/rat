from core.protocol.ratsocket import RATSocket


class ClientTransport(RATSocket):
    """
    客户端底层传输对象。
    仅保留普通消息收发。
    """

    def __init__(self, sock, address=None):
        super().__init__()
        self.socket = sock
        self.address = address



