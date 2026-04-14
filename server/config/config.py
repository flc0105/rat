import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(BASE_DIR)

# ------------------ network ------------------ #
SOCKET_HOST = ''
SOCKET_PORT = 9999
SOCKET_ADDR = (SOCKET_HOST, SOCKET_PORT)

WEB_HOST = '0.0.0.0'
WEB_PORT = 8085

# ------------------ auth ------------------ #
WEB_SESSION_SECRET = os.getenv('RAT_WEB_SESSION_SECRET', 'change-this-session-secret')
ADMIN_USERNAME = os.getenv('RAT_ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('RAT_ADMIN_PASSWORD', 'admin123456')
ADMIN_API_TOKEN = os.getenv('RAT_ADMIN_API_TOKEN', 'change-this-static-token')
WEB_AUTH_SESSION_DAYS = int(os.getenv('RAT_WEB_AUTH_SESSION_DAYS', '7'))
SESSION_COOKIE_NAME = os.getenv('RAT_WEB_SESSION_COOKIE_NAME', 'rat_admin_session')

# ------------------ command / alias ------------------ #
ALIAS_PATH = os.path.join(SERVER_DIR, 'resources/aliases.json')
SCRIPT_PATH = os.path.join(SERVER_DIR, 'resources/scripts')
# 脚本目录
SCRIPT_JOBS_PATH = os.path.join(SERVER_DIR, 'resources/jobs')

# ------------------ logging ------------------ #
BACKGROUND_MESSAGE_OUTPUT_TO_FILE = True
BACKGROUND_MESSAGE_LOG_FILE = 'session_messages.log'

# ------------------ history ------------------ #
COMMAND_HISTORY_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'command_history'))
COMMAND_HISTORY_MAX_ENTRIES_PER_HOST = 300
PINNED_PATHS_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'pinned_paths'))

# ------------------ web files ------------------ #
WEB_FILES_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'web_files'))
# WEB_PREVIEW_TEXT_MAX_BYTES = 200 * 1024
WEB_PREVIEW_TEXT_MAX_BYTES = 200 * 1024
WEB_HTTP_UPLOAD_MAX_BYTES = 10 * 1024 * 1024 * 1024  # 10GB
WEB_CLEAR_PREVIEW_CACHE_ON_STARTUP = True

WEB_PUBLIC_BASE_URL = 'http://127.0.0.1:8085'

HEARTBEAT_INTERVAL_SECONDS = 30

RECENT_DEVICES_JSON_PATH = os.path.abspath(os.path.join('runtime', 'recent_devices.json'))