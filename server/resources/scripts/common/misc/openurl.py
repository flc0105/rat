SCRIPT_METADATA = {
    "name": "common/misc/openurl",
    "display_name": "Open URL",
    "description": "Open a URL in the default browser",
    "platforms": ["common"],
    "category": "Misc",
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

from core.utils.client_util import require_kwarg

url = require_kwarg(kwargs, 'url')
webbrowser.open(url)
