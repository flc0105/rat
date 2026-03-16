import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(BASE_DIR)

SOCKET_ADDR = ('', 9999)

ALIAS_PATH = os.path.join(BASE_DIR, 'aliases_mac.json')
SCRIPT_PATH = os.path.join(SERVER_DIR, 'scripts')

BACKGROUND_MESSAGE_OUTPUT_TO_FILE = True
SHOW_MESSAGES_FROM_OTHER_CONNECTIONS = False