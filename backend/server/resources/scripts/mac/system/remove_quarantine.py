SCRIPT_METADATA = {
    "name": "macos/file/remove_quarantine",
    "display_name": "Remove Quarantine Attribute",
    "description": "Remove the com.apple.quarantine extended attribute from a file to bypass Gatekeeper",
    "category": "System",
    "platforms": ["macos"],
    "params": [
        {
            "name": "target_file",
            "type": "remote_file",
            "description": "Target file to remove quarantine from",
            "required": True,
            "initial_path": "."
        }
    ]
}

import os
import sys
import tempfile

from client.runtime.sdk import command

file = kwargs.get("target_file")
if file:
    result = command.run_shell('xattr -d com.apple.quarantine ' + file)
    print('result =', result)
    print('returncode =', result.returncode)
    print('stdout =', result.stdout.strip())
    print('stderr =', result.stderr.strip())
else:
    print('No file selected')