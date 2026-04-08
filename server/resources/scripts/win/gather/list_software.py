# -*- coding: utf-8 -*-

import json
import winreg


UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def safe_query_value(key, value_name: str):
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return str(value).strip()
    except (FileNotFoundError, OSError):
        return None


def enum_uninstall_key(root, flag):
    result = []

    try:
        access = winreg.KEY_READ | flag
        with winreg.OpenKey(root, UNINSTALL_PATH, 0, access) as reg_key:
            subkey_count = winreg.QueryInfoKey(reg_key)[0]

            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    with winreg.OpenKey(reg_key, subkey_name) as subkey:
                        name = safe_query_value(subkey, "DisplayName")
                        if not name:
                            continue

                        version = safe_query_value(subkey, "DisplayVersion") or "N/A"
                        publisher = safe_query_value(subkey, "Publisher") or "N/A"

                        result.append({
                            "name": name,
                            "version": version,
                            "publisher": publisher
                        })
                except OSError:
                    continue
                except Exception:
                    continue
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return result


result = []
seen = set()

try:
    registry_sources = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, 0)
    ]

    for root, flag in registry_sources:
        for item in enum_uninstall_key(root, flag):
            unique_key = (
                item["name"].lower(),
                item["version"].lower(),
                item["publisher"].lower()
            )
            if unique_key in seen:
                continue
            seen.add(unique_key)
            result.append(item)

    result.sort(key=lambda x: x["name"].lower())
    print(json.dumps(result, ensure_ascii=False, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}, ensure_ascii=False))

