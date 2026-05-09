SCRIPT_METADATA = {
    "name": "win/forensics/powershell_history",
    "display_name": "PowerShell History",
    "description": "Read PowerShell command history from local user profiles",
    "platforms": ["windows"],
    "category": "Forensics",
    "params": []
}

import os
import glob
from pathlib import Path
from datetime import datetime


def read_lines(path):
    for enc in ("utf-8-sig", "utf-8", "utf-16", "gbk", "latin-1"):
        try:
            with open(path, "r", encoding=enc, errors="replace") as f:
                return f.read().splitlines()
        except Exception:
            pass
    return []


def file_mtime(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def get_profiles():
    users_dir = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    profiles = []

    if users_dir.exists():
        for p in users_dir.iterdir():
            if p.is_dir():
                profiles.append(p)

    current = os.environ.get("USERPROFILE")
    if current:
        p = Path(current)
        if p not in profiles:
            profiles.append(p)

    return profiles


def find_history_files(profile):
    patterns = [
        profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "*_history.txt",
        profile / "AppData" / "Roaming" / "Microsoft" / "PowerShell" / "PSReadLine" / "*_history.txt",
        profile / "Documents" / "PowerShell" / "PSReadLine" / "*_history.txt",
        profile / "Documents" / "WindowsPowerShell" / "PSReadLine" / "*_history.txt",
    ]

    files = []
    for pattern in patterns:
        files.extend(glob.glob(str(pattern)))

    return [f for f in files if os.path.isfile(f)]


seen = set()
history_files = []

for profile in get_profiles():
    for path in find_history_files(profile):
        key = os.path.abspath(path).lower()
        if key not in seen:
            seen.add(key)
            history_files.append(path)

if not history_files:
    print("No PowerShell history files found.")

for path in history_files:
    print("=" * 80)
    print("Path:", path)
    print("Last Modified:", file_mtime(path))
    print("=" * 80)

    lines = read_lines(path)
    for line in lines:
        print(line)

    print()