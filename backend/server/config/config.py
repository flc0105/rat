import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(BASE_DIR)

# ------------------ network ------------------ #
SOCKET_HOST = ''
SOCKET_PORT = 9999
SOCKET_ADDR = (SOCKET_HOST, SOCKET_PORT)

WEB_HOST = '0.0.0.0'
WEB_PORT = 8085
WEB_WS_PORT = int(os.getenv('RCH_WEB_WS_PORT', str(WEB_PORT + 1)))
WEB_FILE_TRANSFER_PORT = WEB_PORT + 2

# ------------------ auth ------------------ #
WEB_SESSION_SECRET = os.getenv('RCH_WEB_SESSION_SECRET', 'BE18F48E-F363-458A-8F29-5E6C791C8F03')
ADMIN_USERNAME = os.getenv('RCH_ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('RCH_ADMIN_PASSWORD', 'mutsumi123456')
ADMIN_API_TOKEN = os.getenv('RCH_ADMIN_API_TOKEN', '627D3547-E8F4-4705-AABC-D42EB872F4D6')
HIDDEN_DEVICES_REQUIRE_PASSWORD = os.getenv('RCH_HIDDEN_DEVICES_REQUIRE_PASSWORD', 'true').strip().lower() in {
    '1', 'true', 'yes', 'on',
}
HIDDEN_DEVICES_PASSWORD = os.getenv('RCH_HIDDEN_DEVICES_PASSWORD', '1')
WEB_AUTH_SESSION_DAYS = int(os.getenv('RCH_WEB_AUTH_SESSION_DAYS', '7'))
SESSION_COOKIE_NAME = os.getenv('RCH_WEB_SESSION_COOKIE_NAME', 'rch_admin_session')

# ------------------ command / alias ------------------ #
ALIAS_PATH = os.path.join(SERVER_DIR, 'resources/aliases.json')
SCRIPT_PATH = os.path.join(SERVER_DIR, 'resources/scripts')
# 脚本目录
SCRIPT_JOBS_PATH = os.path.join(SERVER_DIR, 'resources/jobs')

# ------------------ external tools ------------------ #
EXTERNAL_TOOLS_ROOT = os.path.join(SERVER_DIR, 'resources/external_tools')
EXTERNAL_TOOL_META_PATH = os.path.join(EXTERNAL_TOOLS_ROOT, 'metas')
EXTERNAL_TOOL_PACKAGE_PATH = os.path.join(EXTERNAL_TOOLS_ROOT, 'packages')
EXTERNAL_TOOL_PARAM_PRESETS_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'external_tool_param_presets'))

# ------------------ logging ------------------ #
# session_messages.log 已移除，background message 不再单独落盘。
# ------------------ runtime ------------------ #
os.makedirs('runtime', exist_ok=True)

# ------------------ cleanup ------------------ #
SERVER_CLEANUP_START_DELAY_SECONDS = 20
SERVER_CLEANUP_LOG_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'cleanup_logs'))
SERVER_CLEANUP_ITEMS = (
    'notifications',
    'agent_build_temp',
    'agent_transient_outputs',
    'preview_cache',
    'upload_tmp',
    'cleanup_logs',
)

# ------------------ history ------------------ #
COMMAND_HISTORY_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'command_history'))
CONNECTION_HISTORY_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'connection_history'))
COMMAND_HISTORY_MAX_ENTRIES_PER_HOST = 300
COMMAND_HISTORY_MAX_OUTPUT_RECORD_CHARS = 8 * 1024
COMMAND_HISTORY_MAX_OUTPUT_SUMMARY_CHARS = 240
COMMAND_HISTORY_MAX_OUTPUT_RECORDS = 20
# 一台机器最多 300 条命令历史；
# 每条命令历史里，最多 20 段输出；
# 每条命令历史总输出文本最多 8KB。
PINNED_PATHS_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'pinned_paths'))
KEYCHAINS_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'keychains'))

# ------------------ web files ------------------ #
WEB_FILES_ROOT_DIR = os.path.abspath(os.path.join('runtime', 'web_files'))
# WEB_PREVIEW_TEXT_MAX_BYTES = 200 * 1024
WEB_PREVIEW_TEXT_MAX_BYTES = 200 * 1024
WEB_HTTP_UPLOAD_MAX_BYTES = 10 * 1024 * 1024 * 1024  # 10GB
WEB_PUBLIC_BASE_URL = 'http://127.0.0.1:8085'

HEARTBEAT_INTERVAL_SECONDS = 30

RECENT_DEVICES_JSON_PATH = os.path.abspath(os.path.join('runtime', 'recent_devices.json'))
DEVICE_GROUPS_JSON_PATH = os.path.abspath(os.path.join('runtime', 'device_groups.json'))
TOOLBAR_PREFERENCES_JSON_PATH = os.path.abspath(os.path.join('runtime', 'toolbar_preferences.json'))
NOTIFICATION_PREFERENCES_JSON_PATH = os.path.abspath(os.path.join('runtime', 'notification_preferences.json'))
NOTIFICATION_CENTER_JSON_PATH = os.path.abspath(os.path.join('runtime', 'notification_center.json'))
