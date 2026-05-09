import sys

from client.bootstrap.client_app import Client
from client.config.config import SERVER_ADDR
from client.watchdog.watchdog_process import run_watchdog_worker_from_argv
from core.utils.logger import logger


def main():
    if '--watchdog-worker' in sys.argv[1:]:
        run_watchdog_worker_from_argv()
        sys.exit(0)

    client = Client(SERVER_ADDR)
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        client.guard_manager.stop()
        sys.exit(0)
    except Exception as e:
        client.guard_manager.stop()
        logger.error(e, exc_info=True)


if __name__ == '__main__':
    main()
