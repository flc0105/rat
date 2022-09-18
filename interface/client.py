import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from core.client import Client

if __name__ == '__main__':
    client = Client()
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        sys.exit(0)
