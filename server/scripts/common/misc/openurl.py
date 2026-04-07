import webbrowser
from core.utils.client_util import require_kwarg

# add 打开网址参数校验 2026-04-07 00:00
url = require_kwarg(kwargs, 'url')
webbrowser.open(url)