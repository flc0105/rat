#!/usr/bin/env python3
import os
import json
from collections import Counter

# ======================
# config
# ======================
LIMIT = 20


# ======================
# utils
# ======================
def get_zsh_history():
    path = os.path.expanduser("~/.zsh_history")
    if not os.path.exists(path):
        raise FileNotFoundError("~/.zsh_history not found")
    return path


def parse_zsh_history(path):
    """
    支持 EXTENDED_HISTORY:
    : 1700000000:0;git status
    """
    commands = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # 有时间戳
            if line.startswith(": "):
                try:
                    _, rest = line.split(";", 1)
                    cmd = rest.strip()
                except ValueError:
                    continue
            else:
                # fallback（极少见）
                cmd = line

            if not cmd:
                continue

            # 只取第一个 token
            first = cmd.split()[0]

            # 忽略自己
            if first == "command-stats":
                continue

            commands.append(first)

    return commands


# ======================
# main
# ======================
def main():
    history_path = get_zsh_history()
    commands = parse_zsh_history(history_path)

    if not commands:
        print(json.dumps([]))
        return

    counter = Counter(commands)

    result = [
        {"command": cmd, "count": count}
        for cmd, count in counter.most_common(LIMIT)
    ]

    print(json.dumps(result, ensure_ascii=False, indent=2))


main()