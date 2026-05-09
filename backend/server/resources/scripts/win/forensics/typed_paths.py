SCRIPT_METADATA = {
    "name": "win/forensics/typed_paths",
    "display_name": "Typed Paths",
    "description": "Parse Explorer typed path records from user hives",
    "platforms": ["windows"],
    "category": "Forensics",
    "params": []
}

import os
import json
import glob
import ctypes
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

try:
    import winreg
except ImportError:
    print("[]")
    raise SystemExit


TYPEDPATHS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"


def filetime_to_string(value):
    try:
        if not value:
            return ""

        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = base + timedelta(microseconds=value / 10)

        if dt.year < 1980 or dt.year > 2100:
            return ""

        return dt.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % (dt.microsecond // 1000)
    except Exception:
        return ""


def reg_time_to_string(value):
    return filetime_to_string(value)


def read_typedpaths(root, root_path, subkey):
    rows = []

    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            _, _, last_write_time = winreg.QueryInfoKey(k)

            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(k, i)
                    i += 1

                    rows.append({
                        "path": root_path + "\\" + TYPEDPATHS_KEY,
                        "last_write_time": reg_time_to_string(last_write_time),
                        "value_name": value_name,
                        "typed_path": value_data if isinstance(value_data, str) else str(value_data)
                    })

                except OSError:
                    break

    except Exception:
        pass

    return rows


def enum_hku():
    sids = []

    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as hku:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(hku, i)
                    i += 1

                    if sid.endswith("_Classes"):
                        continue

                    if sid == ".DEFAULT" or sid.startswith("S-1-5-"):
                        sids.append(sid)

                except OSError:
                    break
    except Exception:
        pass

    return sorted(set(sids))


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(cmd):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False
        )
        return p.returncode
    except Exception:
        return -1


def load_hive(hive_path, mount_name):
    return run_cmd(["reg.exe", "load", "HKU\\" + mount_name, hive_path]) == 0


def unload_hive(mount_name):
    run_cmd(["reg.exe", "unload", "HKU\\" + mount_name])


def find_ntuser_hives():
    users_dir = Path(os.environ.get("SystemDrive", "C:") + "\\Users")

    if not users_dir.exists():
        return []

    return [
        p for p in glob.glob(str(users_dir / "*" / "NTUSER.DAT"))
        if os.path.isfile(p)
    ]


result = []
seen = set()


def add_items(items):
    for item in items:
        key = (
            item.get("path", ""),
            item.get("value_name", ""),
            item.get("typed_path", "")
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)


for sid in enum_hku():
    add_items(read_typedpaths(
        winreg.HKEY_USERS,
        "HKU\\" + sid,
        sid + "\\" + TYPEDPATHS_KEY
    ))

if is_admin():
    for hive in find_ntuser_hives():
        mount_name = "_typedpaths_" + str(abs(hash(hive)))

        if load_hive(hive, mount_name):
            try:
                add_items(read_typedpaths(
                    winreg.HKEY_USERS,
                    "HKU\\" + mount_name,
                    mount_name + "\\" + TYPEDPATHS_KEY
                ))
            finally:
                unload_hive(mount_name)

result.sort(key=lambda x: (
    x.get("path", ""),
    x.get("value_name", "")
))

print(json.dumps(result, ensure_ascii=False, indent=2))