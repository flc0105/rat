SCRIPT_METADATA = {
    "name": "common/recon/wechat_files",
    "display_name": "WeChat File Scanner",
    "description": "Scan and enumerate WeChat data directories",
    "platforms": ["common"],
    "category": "Recon",
    "params": []
}

import os
import re
import platform
from pathlib import Path
from datetime import datetime


WXID_RE = re.compile(r"^wxid_[0-9A-Za-z_-]+$")

TREE_MAX_DEPTH = 6
TREE_MAX_ENTRIES = 3000

SKIP_DIR_NAMES = {
    ".git",
    ".cache",
    "__pycache__",
    "node_modules",
    "$RECYCLE.BIN",
    "System Volume Information",
}


def human_size(num):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024


def format_time(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def safe_stat(path):
    try:
        return path.stat()
    except Exception:
        return None


def get_wechat_data_root():
    home = Path.home()
    system = platform.system().lower()

    if "darwin" in system:
        return (
            home
            / "Library"
            / "Containers"
            / "com.tencent.xinWeChat"
            / "Data"
            / "Documents"
            / "xwechat_files"
        )

    if "windows" in system:
        userprofile = Path(os.environ.get("USERPROFILE", str(home)))

        candidates = [
            userprofile / "Documents" / "WeChat Files",
            userprofile / "文档" / "WeChat Files",
            userprofile / "My Documents" / "WeChat Files",
        ]

        for env_name in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]:
            one_drive = os.environ.get(env_name)
            if one_drive:
                one_drive = Path(one_drive)
                candidates.extend([
                    one_drive / "Documents" / "WeChat Files",
                    one_drive / "文档" / "WeChat Files",
                ])

        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate

        return candidates[0]

    return home / "Documents" / "WeChat Files"


def find_case_child(parent, target_name):
    if not parent.exists() or not parent.is_dir():
        return None

    target_name = target_name.lower()

    try:
        for child in parent.iterdir():
            if child.is_dir() and not child.is_symlink():
                if child.name.lower() == target_name:
                    return child
    except Exception:
        return None

    return None


def find_wxid_dirs(root):
    if not root.exists() or not root.is_dir():
        return []

    wxid_dirs = []

    try:
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                if WXID_RE.match(child.name):
                    wxid_dirs.append(child)
    except Exception:
        return []

    wxid_dirs.sort(key=lambda p: p.name.lower())
    return wxid_dirs


def join_case_path(base, names):
    current = base

    for name in names:
        current = find_case_child(current, name)
        if current is None:
            return None

    return current


def find_file_target_dir(wxid_dir):
    system = platform.system().lower()

    if "windows" in system:
        return join_case_path(wxid_dir, ["FileStorage", "File"])

    if "darwin" in system:
        candidates = [
            ["Msg", "File"],
            ["FileStorage", "File"],
        ]

        for parts in candidates:
            path = join_case_path(wxid_dir, parts)
            if path:
                return path

        return None

    candidates = [
        ["FileStorage", "File"],
        ["Msg", "File"],
    ]

    for parts in candidates:
        path = join_case_path(wxid_dir, parts)
        if path:
            return path

    return None


def scan_tree_stats(root):
    """
    Recursively scan one directory.

    Size means total regular file size under this directory.
    Directory inode size is not counted.
    File contents are not read.
    """
    total_size = 0
    file_count = 0
    dir_count = 0
    latest_modified = None
    latest_accessed = None
    errors = 0

    stack = [root]

    while stack:
        current = stack.pop()

        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue

                        stat = entry.stat(follow_symlinks=False)

                        if latest_modified is None or stat.st_mtime > latest_modified:
                            latest_modified = stat.st_mtime

                        if latest_accessed is None or stat.st_atime > latest_accessed:
                            latest_accessed = stat.st_atime

                        if entry.is_file(follow_symlinks=False):
                            file_count += 1
                            total_size += stat.st_size

                        elif entry.is_dir(follow_symlinks=False):
                            dir_count += 1

                            if entry.name not in SKIP_DIR_NAMES:
                                stack.append(Path(entry.path))

                    except Exception:
                        errors += 1

        except Exception:
            errors += 1

    return {
        "size_bytes": total_size,
        "file_count": file_count,
        "dir_count": dir_count,
        "latest_modified_ts": latest_modified,
        "latest_accessed_ts": latest_accessed,
        "errors": errors,
    }


def print_stats(title, stats):
    print(title)
    print(f"  Size: {human_size(stats['size_bytes'])} ({stats['size_bytes']} bytes)")
    print(f"  Files: {stats['file_count']}")
    print(f"  Directories: {stats['dir_count']}")
    print(f"  Latest modified: {format_time(stats['latest_modified_ts'])}")
    print(f"  Latest accessed: {format_time(stats['latest_accessed_ts'])}")
    print(f"  Scan errors: {stats['errors']}")


def print_tree(root):
    count = 0
    truncated = False

    print(f"{root}/")

    def walk(current, prefix, depth):
        nonlocal count, truncated

        if depth > TREE_MAX_DEPTH:
            return

        if count >= TREE_MAX_ENTRIES:
            truncated = True
            return

        try:
            entries = [
                p for p in current.iterdir()
                if not p.is_symlink()
            ]
        except Exception:
            print(prefix + "[Access denied]")
            return

        entries.sort(key=lambda p: (not p.is_dir(), p.name.lower()))

        for index, item in enumerate(entries):
            if count >= TREE_MAX_ENTRIES:
                truncated = True
                return

            connector = "└── " if index == len(entries) - 1 else "├── "
            next_prefix = prefix + ("    " if index == len(entries) - 1 else "│   ")

            label = item.name

            if item.is_file():
                stat = safe_stat(item)
                if stat:
                    label += f" ({human_size(stat.st_size)})"

            print(prefix + connector + label)
            count += 1

            if item.is_dir() and item.name not in SKIP_DIR_NAMES:
                walk(item, next_prefix, depth + 1)

    walk(root, "", 1)

    if truncated:
        print()
        print(f"[Tree truncated. Showing first {TREE_MAX_ENTRIES} entries only.]")


def main():
    data_root = get_wechat_data_root()

    print("=" * 100)
    print("WeChat File Directory Scanner")
    print("=" * 100)
    print(f"System: {platform.system()} {platform.release()}")
    print(f"User home: {Path.home()}")
    print(f"WeChat data root: {data_root}")
    print()

    if not data_root.exists() or not data_root.is_dir():
        print("WeChat data root was not found.")
        return

    print("Scanning data root stats...")
    data_root_stats = scan_tree_stats(data_root)

    wxid_dirs = find_wxid_dirs(data_root)

    print()
    print("Overview")
    print(f"  wxid account directories found: {len(wxid_dirs)}")
    print()

    print_stats("Data root stats", data_root_stats)
    print()

    if not wxid_dirs:
        print("No wxid_* account directories were found.")
        return

    for wxid_dir in wxid_dirs:
        account_stats = scan_tree_stats(wxid_dir)
        file_target_dir = find_file_target_dir(wxid_dir)

        print("=" * 100)
        print(f"Account: {wxid_dir.name}")
        print(f"Account directory: {wxid_dir}")
        print()

        print_stats("Account stats", account_stats)
        print()

        if not file_target_dir:
            print("File target directory was not found.")
            print()
            continue

        file_stats = scan_tree_stats(file_target_dir)

        print(f"File target directory: {file_target_dir}")
        print()

        print_stats("File directory stats", file_stats)
        print()

        print("Tree")
        print("-" * 100)
        print_tree(file_target_dir)
        print()

    print("=" * 100)
    print("Done.")


if __name__ == "__main__":
    main()