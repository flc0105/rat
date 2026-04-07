import webbrowser

from core.utils.client_util import require_kwarg

url = require_kwarg(kwargs, 'url')
webbrowser.open(url)
