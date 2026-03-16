import threading

from server.config.config import SOCKET_ADDR
from ratserver import Server
from server.web.app import create_app


def main():
    server = Server(SOCKET_ADDR)

    threading.Thread(target=server.serve, daemon=True).start()

    app = create_app(server)
    app.run(host='0.0.0.0', port=5001, threaded=True, debug=False)


if __name__ == '__main__':
    main()