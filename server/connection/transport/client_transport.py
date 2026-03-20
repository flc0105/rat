from core.protocol.base_connection import BaseSessionConnection


class ClientTransport(BaseSessionConnection):
    """
    客户端底层传输对象。

    职责：
    - 持有 socket / address
    - 提供底层 send / recv / file transfer / ready queue 能力
    - 不承载 session runtime / history / web context / services
    """

    FILE_TRANSFER_REJECTED_MESSAGE = 'Client rejected file transfer'

    def __init__(self, sock, address=None):
        super().__init__()
        self.socket = sock
        self.address = address