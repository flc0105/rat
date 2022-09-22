import contextlib
import json

from config.server import STATIC_URL


def notify(info):
    with contextlib.suppress(Exception):
        import requests
        requests.post('{}/notify'.format(STATIC_URL), json=json.dumps(info))
