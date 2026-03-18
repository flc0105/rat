import os

# ------------------ network ------------------ #
# SERVER_HOST = '39.107.248.76'
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
SERVER_ADDR = (SERVER_HOST, SERVER_PORT)

SERVER_WEB_SCHEME = 'http'
SERVER_WEB_HOST = '127.0.0.1'
# SERVER_WEB_HOST = '39.107.248.76'
# SERVER_WEB_PORT = 8085
SERVER_WEB_PORT = 5001
UPLOAD_BASE_URL = f'{SERVER_WEB_SCHEME}://{SERVER_WEB_HOST}:{SERVER_WEB_PORT}'

RECONNECT_INTERVAL_SECONDS = 5

# ------------------ paths ------------------ #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.dirname(BASE_DIR)
JOB_PATH = os.path.join(CLIENT_DIR, 'jobs', 'builtins')