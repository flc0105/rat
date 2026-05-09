#!/usr/bin/env python3
import os
import pwd
import json
import sqlite3
import datetime as dt
import subprocess
from pathlib import Path

SERVICE = "kTCCServiceSystemPolicyAllFiles"

SKIP_USERS = {
    "Shared",
    ".localized",
}

AUTH_VALUE_MAP = {
    0: "denied",
    1: "unknown_or_prompt",
    2: "allowed",
    3: "limited",
}

CLIENT_TYPE_MAP = {
    0: "bundle_id",
    1: "absolute_path",
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


def unix_to_local(value):
    if value is None:
        return None

    try:
        value = int(value)
        if value <= 0:
            return None
        return dt.datetime.fromtimestamp(value).isoformat(timespec="seconds")
    except Exception:
        return None


def table_columns(conn, table):
    try:
        return [
            row[1]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        ]
    except Exception:
        return []


def sql_expr(col, cols):
    if col in cols:
        return col
    return f"NULL AS {col}"


def query_tcc_db(scope, owner, db_path):
    rows = []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    cols = table_columns(conn, "access")

    wanted_cols = [
        "service",
        "client",
        "client_type",
        "auth_value",
        "auth_reason",
        "auth_version",
        "flags",
        "last_modified",
    ]

    select_list = ", ".join(sql_expr(c, cols) for c in wanted_cols)

    sql = f"""
    SELECT {select_list}
    FROM access
    WHERE service = ?
    ORDER BY last_modified DESC, client_type, client
    """

    for row in conn.execute(sql, (SERVICE,)):
        client_type = row["client_type"]
        auth_value = row["auth_value"]

        rows.append({
            "scope": scope,
            "owner": owner,
            "service": row["service"],
            "service_name": "Full Disk Access",
            "client": row["client"],
            "client_type": client_type,
            "client_type_name": CLIENT_TYPE_MAP.get(client_type, "unknown"),
            "auth_value": auth_value,
            "decision": AUTH_VALUE_MAP.get(auth_value, "unknown"),
            "allowed": auth_value == 2,
            "auth_reason": row["auth_reason"],
            "auth_version": row["auth_version"],
            "flags": row["flags"],
            "last_modified": row["last_modified"],
            "last_modified_local": unix_to_local(row["last_modified"]),
            "db_path": str(db_path),
        })

    conn.close()
    return rows


def main():
    output = []

    db_targets = [
        {
            "scope": "system",
            "owner": "system",
            "path": Path("/Library/Application Support/com.apple.TCC/TCC.db"),
        }
    ]

    for username, home in get_target_users().items():
        db_targets.append({
            "scope": "user",
            "owner": username,
            "path": home / "Library/Application Support/com.apple.TCC/TCC.db",
        })

    seen = set()

    for item in db_targets:
        db_path = item["path"]
        key = str(db_path)

        if key in seen:
            continue
        seen.add(key)

        if not db_path.exists():
            continue

        try:
            output.extend(
                query_tcc_db(
                    scope=item["scope"],
                    owner=item["owner"],
                    db_path=db_path,
                )
            )
        except Exception as e:
            output.append({
                "scope": item["scope"],
                "owner": item["owner"],
                "db_path": str(db_path),
                "error": str(e),
            })

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()