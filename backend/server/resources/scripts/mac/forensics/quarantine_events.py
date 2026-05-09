#!/usr/bin/env python3
import json
import shutil
import sqlite3
import tempfile
import datetime as dt
from pathlib import Path

LIMIT = 500

COCOA_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)


def cocoa_time_to_local_iso(value):
    if value is None:
        return None

    try:
        utc_time = COCOA_EPOCH + dt.timedelta(seconds=float(value))
        return utc_time.astimezone().isoformat(timespec="seconds")
    except Exception:
        return None


def copy_sqlite_db(src, tmpdir):
    copied = tmpdir / src.name
    shutil.copy2(src, copied)

    for suffix in ["-wal", "-shm"]:
        sidecar = Path(str(src) + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, tmpdir / (src.name + suffix))

    return copied


def get_user_homes():
    homes = []

    current_home = Path.home()
    if current_home.exists():
        homes.append(current_home)

    users_dir = Path("/Users")
    if users_dir.exists():
        for p in users_dir.iterdir():
            if p.is_dir() and not p.name.startswith(".") and p.name != "Shared":
                homes.append(p)

    unique = []
    seen = set()

    for h in homes:
        key = str(h)
        if key not in seen:
            seen.add(key)
            unique.append(h)

    return unique


def find_quarantine_dbs():
    dbs = []

    for home in get_user_homes():
        main_db = home / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        if main_db.exists():
            dbs.append((home.name, main_db))

        containers = home / "Library/Containers"
        if containers.exists():
            for db in containers.glob("*/Data/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"):
                if db.exists():
                    dbs.append((home.name, db))

    return dbs


def query_db(username, db_path):
    rows = []

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        copied_db = copy_sqlite_db(db_path, tmpdir)

        conn = sqlite3.connect(f"file:{copied_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        sql = """
        SELECT
            LSQuarantineEventIdentifier,
            LSQuarantineTimeStamp,
            LSQuarantineAgentBundleIdentifier,
            LSQuarantineAgentName,
            LSQuarantineTypeNumber,
            LSQuarantineDataURLString,
            LSQuarantineOriginURLString
        FROM LSQuarantineEvent
        ORDER BY LSQuarantineTimeStamp DESC
        LIMIT ?
        """

        for row in conn.execute(sql, (LIMIT,)):
            rows.append({
                "time": cocoa_time_to_local_iso(row["LSQuarantineTimeStamp"]),
                "event_id": row["LSQuarantineEventIdentifier"],
                "agent": row["LSQuarantineAgentName"],
                "agent_bundle_id": row["LSQuarantineAgentBundleIdentifier"],
                "type_number": row["LSQuarantineTypeNumber"],
                "data_url": row["LSQuarantineDataURLString"],
                "origin_url": row["LSQuarantineOriginURLString"],
                "user": username,
                "db_path": str(db_path),
            })

        conn.close()

    return rows


def main():
    output = []

    for username, db_path in find_quarantine_dbs():
        try:
            output.extend(query_db(username, db_path))
        except Exception:
            pass

    output.sort(key=lambda x: x.get("time") or "", reverse=True)

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()