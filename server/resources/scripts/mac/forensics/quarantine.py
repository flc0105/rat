#!/usr/bin/env python3
import csv
import json
import os
import shutil
import sqlite3
import tempfile
import datetime as dt
from pathlib import Path

COCOA_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)

def cocoa_to_iso(value):
    if value is None:
        return None
    try:
        return (COCOA_EPOCH + dt.timedelta(seconds=float(value))).isoformat()
    except Exception:
        return None

def copy_sqlite_with_sidecars(db_path: Path, dst_dir: Path) -> Path:
    dst = dst_dir / db_path.name
    for suffix in ["", "-wal", "-shm"]:
        src = Path(str(db_path) + suffix)
        if src.exists():
            shutil.copy2(src, dst_dir / src.name)
    return dst

def query_quarantine_db(db_path: Path, limit=500):
    rows = []

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        copied_db = copy_sqlite_with_sidecars(db_path, td)

        conn = sqlite3.connect(f"file:{copied_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        tables = [
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        ]

        if "LSQuarantineEvent" not in tables:
            return rows

        cols = [
            r["name"]
            for r in conn.execute("PRAGMA table_info(LSQuarantineEvent)")
        ]

        sql = f"""
        SELECT {", ".join(cols)}
        FROM LSQuarantineEvent
        ORDER BY LSQuarantineTimeStamp DESC
        LIMIT ?
        """

        for row in conn.execute(sql, (limit,)):
            item = dict(row)
            item["db_path"] = str(db_path)
            item["LSQuarantineTimeStamp_UTC"] = cocoa_to_iso(
                item.get("LSQuarantineTimeStamp")
            )
            rows.append(item)

        conn.close()

    return rows

def candidate_dbs():
    seen = set()

    paths = [
        Path.home() / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    ]

    paths.extend(
        Path.home().glob(
            "Library/Containers/*/Data/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        )
    )

    if os.geteuid() == 0:
        paths.extend(
            Path("/Users").glob(
                "*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
            )
        )
        paths.extend(
            Path("/Users").glob(
                "*/Library/Containers/*/Data/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
            )
        )

    for p in paths:
        p = p.expanduser()
        if p.exists() and p not in seen:
            seen.add(p)
            yield p

def write_outputs(rows, out_prefix="quarantine_events"):
    json_path = Path(out_prefix + ".json")
    csv_path = Path(out_prefix + ".csv")

    json_path.write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    keys = sorted({k for r in rows for k in r.keys()})

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] JSON: {json_path}")
    print(f"[+] CSV : {csv_path}")

def main():
    all_rows = []

    for db in candidate_dbs():
        print(f"[*] querying {db}")
        all_rows.extend(query_quarantine_db(db, limit=1000))

    print(f"[+] total rows: {len(all_rows)}")
    write_outputs(all_rows)

if __name__ == "__main__":
    main()