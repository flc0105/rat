SCRIPT_METADATA = {
    "name": "macos/browser/safari_history",
    "display_name": "Safari Browsing History",
    "description": "Retrieve Safari browsing history",
    "platforms": ["macos"],
    "category": "Browser",
    "params": []
}

import os
import pwd
import json
import sqlite3
import subprocess
from pathlib import Path

LIMIT = 200

SKIP_USERS = {
    "Shared",
    ".localized",
}


def run_cmd(cmd):
    try:
        r = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=5,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def get_console_user():
    user = run_cmd(["/usr/bin/stat", "-f", "%Su", "/dev/console"])

    if user and user not in {"root", "_mbsetupuser", "loginwindow"}:
        return user

    return None


def get_home_for_user(username):
    try:
        return Path(pwd.getpwnam(username).pw_dir)
    except Exception:
        return Path("/Users") / username


def get_target_users():
    users = {}

    console = get_console_user()
    if console:
        users[console] = get_home_for_user(console)

    users_dir = Path("/Users")
    if users_dir.exists():
        for p in users_dir.iterdir():
            if not p.is_dir():
                continue
            if p.name in SKIP_USERS:
                continue
            if p.name.startswith("."):
                continue
            users[p.name] = p

    try:
        uid_user = pwd.getpwuid(os.getuid()).pw_name
        if uid_user != "root":
            users[uid_user] = Path.home()
    except Exception:
        pass

    return users


def table_columns(conn, table):
    try:
        return [
            row[1]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        ]
    except Exception:
        return []


def query_safari_db(username, db_path):
    rows = []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    visit_cols = table_columns(conn, "history_visits")
    item_cols = table_columns(conn, "history_items")

    title_expr = "v.title" if "title" in visit_cols else "NULL"
    load_successful_expr = "v.load_successful" if "load_successful" in visit_cols else "NULL"
    origin_expr = "v.origin" if "origin" in visit_cols else "NULL"
    visit_count_expr = "i.visit_count" if "visit_count" in item_cols else "NULL"

    sql = f"""
    SELECT
        datetime(v.visit_time + 978307200, 'unixepoch', 'localtime') AS local_time,
        {title_expr} AS title,
        i.url AS url,
        {visit_count_expr} AS visit_count,
        {load_successful_expr} AS load_successful,
        {origin_expr} AS origin
    FROM history_visits v
    JOIN history_items i ON i.id = v.history_item
    ORDER BY v.visit_time DESC
    LIMIT ?
    """

    for row in conn.execute(sql, (LIMIT,)):
        rows.append({
            "local_time": row["local_time"],
            "title": row["title"],
            "url": row["url"],
            "visit_count": row["visit_count"],
            "load_successful": row["load_successful"],
            "origin": row["origin"],
            "user": username,
            "db_path": str(db_path),
        })

    conn.close()
    return rows


def main():
    output = []

    for username, home in get_target_users().items():
        db_path = home / "Library/Safari/History.db"

        if not db_path.exists():
            continue

        try:
            output.extend(query_safari_db(username, db_path))
        except Exception as e:
            output.append({
                "user": username,
                "db_path": str(db_path),
                "error": str(e),
            })

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()