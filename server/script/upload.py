import os

import requests

url = "http://123.249.102.1/file/upload"


def upload(filename):
    filename = os.path.abspath(filename)
    if not os.path.isfile(filename):
        print(f'File does not exist: {filename}')
    with open(filename, 'rb') as file:
        with requests.post(url, files={'files': file}, data={'currentDirectory': '/public/'}) as resp:
            print(resp.text)


upload(filename)
