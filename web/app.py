from flask import Flask

from config.server import STATIC_PORT

app = Flask(__name__, static_url_path='', static_folder='static')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=STATIC_PORT)
