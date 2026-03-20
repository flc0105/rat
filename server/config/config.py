import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(BASE_DIR)

# ------------------ network ------------------ #
SOCKET_HOST = ''
SOCKET_PORT = 9999
SOCKET_ADDR = (SOCKET_HOST, SOCKET_PORT)

WEB_HOST = '0.0.0.0'
WEB_PORT = 8085

# ------------------ command / alias ------------------ #
ALIAS_PATH = os.path.join(BASE_DIR, 'aliases.json')
SCRIPT_PATH = os.path.join(SERVER_DIR, 'scripts')

# ------------------ logging ------------------ #
BACKGROUND_MESSAGE_OUTPUT_TO_FILE = True
BACKGROUND_MESSAGE_LOG_FILE = 'session_messages.log'

# ------------------ history ------------------ #
COMMAND_HISTORY_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'command_history'))
COMMAND_HISTORY_MAX_ENTRIES_PER_HOST = 300

# ------------------ web files ------------------ #
WEB_FILES_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'web_files'))
WEB_PREVIEW_TEXT_MAX_BYTES = 200 * 1024
WEB_HTTP_UPLOAD_MAX_BYTES = 50 * 1024 * 1024
WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP = True

WEB_PUBLIC_BASE_URL = 'http://127.0.0.1:8085'