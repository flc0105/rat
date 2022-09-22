from flask import Flask, request
from flask_socketio import SocketIO

from config.server import STATIC_PORT

app = Flask(__name__, static_url_path='', static_folder='static')

socketio = SocketIO(app)


@app.route('/notify', methods=['POST'])
def notify():
    socketio.send(request.get_json())
    return 'success'


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=STATIC_PORT, allow_unsafe_werkzeug=True)
