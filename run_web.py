import threading

import uvicorn

from server.config.config import SOCKET_ADDR, WEB_HOST, WEB_PORT
from ratserver import Server
from server.web.asgi import create_asgi_app


def main():
    server = Server(SOCKET_ADDR)

    threading.Thread(target=server.serve, daemon=True).start()
    threading.Thread(target=server.heartbeat_loop, daemon=True).start()

    app = create_asgi_app(server)
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level='info')


if __name__ == '__main__':
    main()
