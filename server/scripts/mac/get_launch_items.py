#!/usr/bin/env python3
import plistlib
import subprocess
import json
from pathlib import Path


def get_launch_items():
    """获取用户和系统的自启动项目"""
    items = []

    # 用户 LaunchAgents
    user_launch_agents = Path.home() / "Library/LaunchAgents"
    if user_launch_agents.exists():
        for plist in user_launch_agents.glob("*.plist"):
            try:
                with open(plist, 'rb') as f:
                    data = plistlib.load(f)
                    items.append({
                        "name": data.get("Label", plist.stem),
                        "path": str(plist),
                        "type": "LaunchAgent",
                        "scope": "user"
                    })
            except:
                pass

    # 系统 LaunchAgents
    system_launch_agents = Path("/Library/LaunchAgents")
    if system_launch_agents.exists():
        for plist in system_launch_agents.glob("*.plist"):
            try:
                with open(plist, 'rb') as f:
                    data = plistlib.load(f)
                    items.append({
                        "name": data.get("Label", plist.stem),
                        "path": str(plist),
                        "type": "LaunchAgent",
                        "scope": "system"
                    })
            except:
                pass

    # 系统 LaunchDaemons
    system_launch_daemons = Path("/Library/LaunchDaemons")
    if system_launch_daemons.exists():
        for plist in system_launch_daemons.glob("*.plist"):
            try:
                with open(plist, 'rb') as f:
                    data = plistlib.load(f)
                    items.append({
                        "name": data.get("Label", plist.stem),
                        "path": str(plist),
                        "type": "LaunchDaemon",
                        "scope": "system"
                    })
            except:
                pass

    # 登录项 (通过AppleScript获取)
    try:
        result = subprocess.run(
            ['osascript', '-e', 'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            login_items = [item.strip() for item in result.stdout.split(',')]
            for item in login_items:
                items.append({
                    "name": item,
                    "type": "LoginItem",
                    "scope": "user"
                })
    except:
        pass

    return items


print(json.dumps(get_launch_items(), indent=2, ensure_ascii=False))