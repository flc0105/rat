import threading

from server.config.config import SOCKET_ADDR, WEB_HOST, WEB_PORT
from ratserver import Server
from server.web.app import create_app


def main():
    server = Server(SOCKET_ADDR)

    threading.Thread(target=server.serve, daemon=True).start()
    threading.Thread(target=server.heartbeat_loop, daemon=True).start()

    app = create_app(server)
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, debug=False)


if __name__ == '__main__':
    main()


