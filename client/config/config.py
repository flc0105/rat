import configparser
import os
import sys

DEFAULT_SERVER_ADDR = ('127.0.0.1', 9999)
UPLOAD_BASE_URL = 'http://127.0.0.1:5001'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.dirname(BASE_DIR)
JOB_PATH = os.path.join(CLIENT_DIR, 'jobs/builtins')


def _get_runtime_dir():
    """
    获取当前程序运行目录：
    - 开发环境：脚本所在目录
    - 打包环境：可执行文件所在目录
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.realpath(sys.executable))
    return os.path.dirname(os.path.realpath(''.join(sys.argv)))


def _load_server_addr_from_ini(config_path):
    """
    从 ini 配置文件加载服务端地址
    """
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')

    ip = config.get('default', 'ip')
    port = config.getint('default', 'port')
    return ip, port


RUNTIME_DIR = _get_runtime_dir()
CONFIG_FILE = os.path.join(RUNTIME_DIR, 'ratclient.ini')

SERVER_ADDR = DEFAULT_SERVER_ADDR

if os.path.isfile(CONFIG_FILE):
    SERVER_ADDR = _load_server_addr_from_ini(CONFIG_FILE)