SCRIPT_METADATA = {
    "name": "ios/pythonista/force_quit",
    "display_name": "Force Quit Pythonista",
    "description": "Immediately force quit the Pythonista app",
    "platforms": ["ios"],
    "category": "Pythonista",
    "params": []
}

import os
import time


def force_quit_app(delay=0.2):
    print('Force quitting Pythonista...')
    time.sleep(delay)
    os._exit(0)


if __name__ == '__main__':
    force_quit_app()
