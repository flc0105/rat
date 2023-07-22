import configparser
import os.path
import sys

SERVER_ADDR = ('127.0.0.1', 9999)

if not getattr(sys, 'frozen', False):
    dir = os.path.dirname(os.path.realpath(''.join(sys.argv)))
else:
    dir = os.path.dirname(os.path.realpath(sys.executable))

filename = os.path.join(dir, 'ratclient.ini')

if os.path.isfile(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    ip = config.get('default', 'ip')
    port = config.getint('default', 'port')
    SERVER_ADDR = (ip, port)

BACKGROUND_MESSAGE_OUTPUT_TO_FILE = False
