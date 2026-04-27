#!/usr/bin/env python3
# -*- coding: utf-8 -*-

SCRIPT_METADATA = {
    "name": "windows/system/get_os_history",
    "display_name": "Get OS History",
    "description": "Get Windows installation and upgrade history from registry",
    "platforms": ["windows"],
    "category": "System",
    "params": []
}

import json
import datetime
import winreg


def safe_query_value(key, value_name):
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except (FileNotFoundError, OSError):
        return None


def timestamp_to_local_string(value):
    try:
        if value is None:
            return ""
        dt = datetime.datetime.fromtimestamp(int(value))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def read_os_entry(root, subkey_path):
    try:
        with winreg.OpenKey(root, subkey_path, 0, winreg.KEY_READ) as key:
            install_date_raw = safe_query_value(key, "InstallDate")

            return {
                "product_name": safe_query_value(key, "ProductName") or "",
                "release_id": safe_query_value(key, "ReleaseID") or "",
                "current_build": str(safe_query_value(key, "CurrentBuild") or ""),
                "install_date": timestamp_to_local_string(install_date_raw),
                "_install_date_raw": int(install_date_raw) if install_date_raw is not None else 0,
                "registry_path": f"HKLM\\{subkey_path}"
            }
    except (FileNotFoundError, PermissionError, OSError):
        return None


def enum_source_keys():
    base_path = r"SYSTEM\Setup"
    results = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ) as base_key:
            subkey_count = winreg.QueryInfoKey(base_key)[0]

            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(base_key, i)
                    if not subkey_name.startswith("Source"):
                        continue

                    full_path = base_path + "\\" + subkey_name
                    item = read_os_entry(winreg.HKEY_LOCAL_MACHINE, full_path)
                    if item:
                        results.append(item)
                except OSError:
                    continue
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return results


def get_os_history():
    results = []

    results.extend(enum_source_keys())

    current_version = read_os_entry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    )
    if current_version:
        results.append(current_version)

    results.sort(key=lambda x: x.get("_install_date_raw", 0))

    for item in results:
        item.pop("_install_date_raw", None)

    return results


try:
    print(json.dumps(get_os_history(), ensure_ascii=False, indent=2))
except Exception as e:
    print(json.dumps({"error": str(e)}, ensure_ascii=False))