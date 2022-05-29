import os

from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

upload_folder = 'uploads/'
if not os.path.exists(upload_folder):
    os.mkdir(upload_folder)
app.config['UPLOAD_FOLDER'] = upload_folder


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
        return '[+] File uploaded successfully', 200


@app.route('/uploads/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    full_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(full_path, filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
