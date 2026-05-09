SCRIPT_METADATA = {
    "name": "win/forensics/usb_storage",
    "display_name": "USB Storage",
    "description": "Enumerate USB storage devices from registry",
    "platforms": ["windows"],
    "category": "Forensics",
    "params": []
}

import os
import re
import json
import struct
from datetime import datetime, timezone, timedelta

try:
    import winreg
except ImportError:
    print("[]")
    raise SystemExit


USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
MOUNTED_DEVICES_KEY = r"SYSTEM\MountedDevices"
PROPERTY_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"

PROPERTY_TIMES = {
    "00000064": "install_time",
    "00000065": "first_install_time",
    "00000066": "last_arrival_time",
    "00000067": "last_removal_time",
}


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


def read_key_last_write(root, subkey):
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            _, _, last_write_time = winreg.QueryInfoKey(k)
            return filetime_to_string(last_write_time)
    except Exception:
        return ""


def enum_subkeys(root, subkey):
    rows = []

    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    rows.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    return rows


def read_value(root, subkey, name):
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            value, _ = winreg.QueryValueEx(k, name)
            return value
    except Exception:
        return ""


def parse_device_name(device_name):
    result = {
        "device_type": "",
        "vendor": "",
        "product": "",
        "revision": ""
    }

    m = re.match(r"([^&]+)&Ven_(.*?)&Prod_(.*?)&Rev_(.*)", device_name, re.I)
    if not m:
        result["device_type"] = device_name
        return result

    result["device_type"] = m.group(1).replace("_", " ").strip()
    result["vendor"] = m.group(2).replace("_", " ").strip()
    result["product"] = m.group(3).replace("_", " ").strip()
    result["revision"] = m.group(4).replace("_", " ").strip()

    return result


def clean_serial(instance_id):
    if "&" in instance_id:
        base, tail = instance_id.rsplit("&", 1)
        if tail.isdigit():
            return base

    return instance_id


def decode_hex_ascii(value):
    try:
        if not value or len(value) % 2 != 0:
            return ""

        raw = bytes.fromhex(value)
        text = raw.decode("ascii", errors="ignore").strip()

        if not text:
            return ""

        if not all(32 <= ord(c) <= 126 for c in text):
            return ""

        return text
    except Exception:
        return ""


def read_property_time(root, instance_subkey, prop_id):
    prop_subkey = instance_subkey + r"\Properties" + "\\" + PROPERTY_GUID + "\\" + prop_id

    try:
        with winreg.OpenKey(root, prop_subkey, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    _, value, _ = winreg.EnumValue(k, i)
                    i += 1

                    if isinstance(value, bytes) and len(value) >= 8:
                        ts = filetime_to_string(struct.unpack("<Q", value[:8])[0])
                        if ts:
                            return ts

                    if isinstance(value, int):
                        ts = filetime_to_string(value)
                        if ts:
                            return ts

                except OSError:
                    break
    except Exception:
        pass

    return ""


def decode_mounted_device_data(data):
    if not isinstance(data, bytes):
        return ""

    try:
        text = data.decode("utf-16le", errors="ignore")
        text = text.replace("\x00", "").strip()
        text = "".join(c for c in text if c.isprintable()).strip()
        return text
    except Exception:
        return ""


def read_mounted_devices():
    rows = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MOUNTED_DEVICES_KEY, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    i += 1

                    target = decode_mounted_device_data(value)

                    rows.append({
                        "name": name,
                        "target": target
                    })

                except OSError:
                    break
    except Exception:
        pass

    return rows


def find_mount_points(device_name, instance_id, mounted_devices):
    rows = []
    needle = ("USBSTOR#" + device_name + "#" + instance_id).lower()

    for item in mounted_devices:
        target = item.get("target", "")

        if needle in target.lower():
            rows.append({
                "name": item.get("name", ""),
                "target": target
            })

    return rows


def split_mount_points(mount_points):
    drive_letters = []
    volume_guids = []

    for item in mount_points:
        name = item.get("name", "")

        if name.startswith(r"\DosDevices\\"):
            drive_letters.append(name.replace(r"\DosDevices\\", ""))

        if name.startswith(r"\??\Volume{"):
            volume_guids.append(name.replace(r"\??\\", ""))

    return drive_letters, volume_guids


mounted_devices = read_mounted_devices()
result = []

for device_name in enum_subkeys(winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY):
    device_subkey = USBSTOR_KEY + "\\" + device_name
    parsed = parse_device_name(device_name)

    for instance_id in enum_subkeys(winreg.HKEY_LOCAL_MACHINE, device_subkey):
        instance_subkey = device_subkey + "\\" + instance_id
        serial_number = clean_serial(instance_id)
        decoded_serial_number = decode_hex_ascii(serial_number)
        mount_points = find_mount_points(device_name, instance_id, mounted_devices)
        drive_letters, volume_guids = split_mount_points(mount_points)

        item = {
            "path": "HKLM\\" + instance_subkey,
            "last_write_time": read_key_last_write(winreg.HKEY_LOCAL_MACHINE, instance_subkey),
            "device_name": device_name,
            "instance_id": instance_id,
            "serial_number": serial_number,
            "decoded_serial_number": decoded_serial_number,
            "device_type": parsed.get("device_type", ""),
            "vendor": parsed.get("vendor", ""),
            "product": parsed.get("product", ""),
            "revision": parsed.get("revision", ""),
            "friendly_name": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "FriendlyName"),
            "device_desc": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "DeviceDesc"),
            "mfg": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "Mfg"),
            "service": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "Service"),
            "driver": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "Driver"),
            "class_guid": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "ClassGUID"),
            "container_id": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "ContainerID"),
            "parent_id_prefix": read_value(winreg.HKEY_LOCAL_MACHINE, instance_subkey, "ParentIdPrefix"),
            "install_time": "",
            "first_install_time": "",
            "last_arrival_time": "",
            "last_removal_time": "",
            "drive_letters": drive_letters,
            "volume_guids": volume_guids,
            "mount_points": mount_points
        }

        for prop_id, field_name in PROPERTY_TIMES.items():
            item[field_name] = read_property_time(winreg.HKEY_LOCAL_MACHINE, instance_subkey, prop_id)

        result.append(item)

result.sort(key=lambda x: (
    x.get("vendor", ""),
    x.get("product", ""),
    x.get("serial_number", ""),
    x.get("device_type", "")
))

print(json.dumps(result, ensure_ascii=False, indent=2))