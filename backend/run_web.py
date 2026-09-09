import threading

import uvicorn
from werkzeug.serving import make_server

from server.config.config import SOCKET_ADDR, WEB_FILE_TRANSFER_PORT, WEB_HOST, WEB_PORT
from rchserver import Server
from core.utils.logger import logger
from server.web.asgi import create_asgi_app
from server.web.file_transfer_app import create_file_transfer_app


def start_file_transfer_server(server):
    app = create_file_transfer_app(server)
    transfer_server = make_server(WEB_HOST, WEB_FILE_TRANSFER_PORT, app, threaded=True)
    threading.Thread(
        target=transfer_server.serve_forever,
        name='file-transfer-http-server',
        daemon=True,
    ).start()
    logger.info('File transfer HTTP listening on %s:%s', WEB_HOST, WEB_FILE_TRANSFER_PORT)
    return transfer_server


def main():
    server = Server(SOCKET_ADDR)

    threading.Thread(target=server.serve, daemon=True).start()
    threading.Thread(target=server.heartbeat_loop, daemon=True).start()

    transfer_server = start_file_transfer_server(server)
    app = create_asgi_app(server)
    server.schedule_startup_cleanup()
    try:
        uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level='info')
    finally:
        transfer_server.shutdown()


if __name__ == '__main__':
    main()
