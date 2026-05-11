SCRIPT_METADATA = {
    "name": "common/browser/open_url",
    "display_name": "Open URL",
    "description": "Open a URL in the default browser",
    "platforms": ["common"],
    "category": "Browser",
    "params": [
        {
            "name": "url",
            "type": "string",
            "required": True,
            "default": "",
            "description": "Target URL"
        }
    ]
}

import webbrowser

from client.runtime.client_util import require_kwarg

url = require_kwarg(kwargs, 'url')
webbrowser.open(url)
