SCRIPT_METADATA = {
    "name": "mac/gather/get_command_stats",
    "display_name": "Get Command Stats",
    "description": "Get the most frequently used shell commands from zsh history",
    "platforms": ["darwin"],
    "category": "Gather",
    "params": [
        {
            "name": "limit",
            "type": "number",
            "required": False,
            "default": 20,
            "description": "Maximum number of commands to return"
        }
    ]
}

import os
import json
from collections import Counter


def get_zsh_history():
    path = os.path.expanduser("~/.zsh_history")
    if not os.path.exists(path):
        raise FileNotFoundError("~/.zsh_history not found")
    return path


def parse_zsh_history(path):
    commands = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith(": "):
                try:
                    _, rest = line.split(";", 1)
                    cmd = rest.strip()
                except ValueError:
                    continue
            else:
                cmd = line

            if not cmd:
                continue

            first = cmd.split()[0]

            if first == "command-stats":
                continue

            commands.append(first)

    return commands


def main():
    limit = kwargs.get("limit", 20)
    try:
        limit = int(limit)
    except Exception:
        limit = 20

    if limit <= 0:
        limit = 20

    try:
        history_path = get_zsh_history()
        commands = parse_zsh_history(history_path)

        if not commands:
            print(json.dumps([], ensure_ascii=False))
            return

        counter = Counter(commands)

        result = [
            {"command": cmd, "count": count}
            for cmd, count in counter.most_common(limit)
        ]

        print(json.dumps(result, ensure_ascii=False, indent=2))

    except Exception as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))


main()