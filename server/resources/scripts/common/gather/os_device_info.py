SCRIPT_METADATA = {
    "name": "common/recon/os_device_info",
    "display_name": "OS and Device Information",
    "description": "Retrieve human-readable operating system and device model information across Windows, macOS, Linux, and iOS",
    "platforms": ["common"],
    "category": "Recon",
    "params": []
}

import ctypes
import json
import os
import platform
import re
import subprocess
import sys


def _safe_text(value, default='') -> str:
    try:
        if value is None:
            return default
        return str(value)
    except Exception:
        return default


def _run_command_output(command: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return ''
        return (result.stdout or '').strip()
    except Exception:
        return ''


def _read_first_existing_text_file(paths: list[str]) -> str:
    for path in paths:
        try:
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read().strip()
        except Exception:
            continue
    return ''


def _load_libc():
    try:
        return ctypes.CDLL(None)
    except Exception:
        return None


def _sysctl_string(name: str) -> str:
    libc = _load_libc()
    if libc is None:
        return ''

    size = ctypes.c_size_t()
    result = libc.sysctlbyname(
        name.encode('utf-8'),
        None,
        ctypes.byref(size),
        None,
        0,
    )
    if result != 0 or size.value <= 0:
        return ''

    buf = ctypes.create_string_buffer(size.value)
    result = libc.sysctlbyname(
        name.encode('utf-8'),
        buf,
        ctypes.byref(size),
        None,
        0,
    )
    if result != 0:
        return ''

    return buf.value.decode('utf-8', errors='replace').strip('\x00').strip()


def _read_linux_os_release() -> dict:
    content = _read_first_existing_text_file([
        '/etc/os-release',
        '/usr/lib/os-release',
    ])

    data = {}
    if not content:
        return data

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue

        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            data[key] = value

    return data


def _join_non_empty(*parts: str, sep: str = ' ') -> str:
    values = [str(part).strip() for part in parts if str(part or '').strip()]
    return sep.join(values)


def _build_os_display(os_name: str, os_version: str, extra_version: str = '') -> str:
    os_name = _safe_text(os_name).strip()
    os_version = _safe_text(os_version).strip()
    extra_version = _safe_text(extra_version).strip()

    base = _join_non_empty(os_name, os_version)
    if extra_version:
        if base:
            return f'{base} ({extra_version})'
        return extra_version
    return base or 'Unknown'


def _build_device_display(manufacturer: str, model: str) -> str:
    manufacturer = _safe_text(manufacturer).strip()
    model = _safe_text(model).strip()

    if manufacturer and model:
        return f'{manufacturer} {model}'
    if manufacturer:
        return manufacturer
    if model:
        return model
    return 'Unknown'


def _detect_windows_os_name_version() -> tuple[str, str, str]:
    product_name = ''
    display_version = ''
    current_build = ''

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        )

        try:
            product_name, _ = winreg.QueryValueEx(key, 'ProductName')
        except Exception:
            product_name = ''

        try:
            display_version, _ = winreg.QueryValueEx(key, 'DisplayVersion')
        except Exception:
            display_version = ''

        try:
            current_build, _ = winreg.QueryValueEx(key, 'CurrentBuildNumber')
        except Exception:
            current_build = ''
    except Exception:
        pass

    product_name = _safe_text(product_name).strip()
    display_version = _safe_text(display_version).strip()
    current_build = _safe_text(current_build).strip()

    build_number = 0
    try:
        build_number = int(current_build)
    except Exception:
        build_number = 0

    if product_name:
        normalized_name = product_name
        if build_number >= 22000 and product_name.lower().startswith('windows 10'):
            normalized_name = 'Windows 11' + product_name[len('Windows 10'):]

        match = re.match(r'^(Windows)\s+(.+)$', normalized_name, flags=re.IGNORECASE)
        if match:
            os_name = match.group(1)
            os_version = match.group(2).strip()
            return os_name, os_version, display_version

        return 'Windows', normalized_name, display_version

    release = _safe_text(platform.release()).strip()
    version = _safe_text(platform.version()).strip()

    if build_number >= 22000:
        base_version = '11'
    elif release:
        base_version = release
    else:
        base_version = version or 'Unknown'

    return 'Windows', base_version, display_version


def _detect_windows_manufacturer_model() -> tuple[str, str]:
    powershell_cmd = [
        'powershell',
        '-NoProfile',
        '-Command',
        "(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model | ConvertTo-Json -Compress)"
    ]
    output = _run_command_output(powershell_cmd, timeout=8)
    if output:
        try:
            data = json.loads(output)
            manufacturer = _safe_text(data.get('Manufacturer')).strip()
            model = _safe_text(data.get('Model')).strip()
            if manufacturer or model:
                return manufacturer, model
        except Exception:
            pass

    output = _run_command_output(['wmic', 'computersystem', 'get', 'manufacturer,model', '/value'])
    manufacturer = ''
    model = ''
    for line in output.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip().lower()
        value = value.strip()
        if key == 'manufacturer' and value:
            manufacturer = value
        elif key == 'model' and value:
            model = value
    return manufacturer, model


def _detect_linux_os_name_version() -> tuple[str, str]:
    os_release = _read_linux_os_release()

    os_name = (
        _safe_text(os_release.get('NAME')).strip()
        or _safe_text(os_release.get('ID')).strip()
        or 'Linux'
    )

    os_version = (
        _safe_text(os_release.get('VERSION_ID')).strip()
        or _safe_text(os_release.get('VERSION')).strip()
        or _safe_text(platform.release()).strip()
        or 'Unknown'
    )

    return os_name, os_version


def _detect_linux_manufacturer_model() -> tuple[str, str]:
    manufacturer = _read_first_existing_text_file([
        '/sys/devices/virtual/dmi/id/sys_vendor',
        '/sys/class/dmi/id/sys_vendor',
    ])
    model = _read_first_existing_text_file([
        '/sys/devices/virtual/dmi/id/product_name',
        '/sys/class/dmi/id/product_name',
    ])
    return manufacturer, model


def _detect_macos_os_name_version() -> tuple[str, str]:
    version = _safe_text(platform.mac_ver()[0]).strip()
    return 'macOS', version or 'Unknown'


def _detect_macos_manufacturer_model() -> tuple[str, str]:
    manufacturer = 'Apple'
    model = _sysctl_string('hw.model') or _run_command_output(['sysctl', '-n', 'hw.model'])
    return manufacturer, model


def _detect_ios_os_name_version() -> tuple[str, str]:
    try:
        import objc_util

        UIDevice = objc_util.ObjCClass('UIDevice')
        current_device = UIDevice.currentDevice()
        version = _safe_text(current_device.systemVersion()).strip()
        return 'iOS', version or 'Unknown'
    except Exception:
        version = _safe_text(platform.release()).strip()
        return 'iOS', version or 'Unknown'


def _detect_ios_manufacturer_model() -> tuple[str, str]:
    manufacturer = 'Apple'
    model = _sysctl_string('hw.machine') or _safe_text(platform.machine()).strip()
    return manufacturer, model


def detect_os_and_device_info() -> dict:
    system_name = platform.system()

    if system_name == 'Windows':
        os_name, os_version, extra_version = _detect_windows_os_name_version()
        manufacturer, model = _detect_windows_manufacturer_model()
        return {
            'os_display': _build_os_display(os_name, os_version, extra_version),
            'device_display': _build_device_display(manufacturer, model),
        }

    if system_name == 'Linux':
        os_name, os_version = _detect_linux_os_name_version()
        manufacturer, model = _detect_linux_manufacturer_model()
        return {
            'os_display': _build_os_display(os_name, os_version),
            'device_display': _build_device_display(manufacturer, model),
        }

    if system_name == 'Darwin':
        if sys.platform == 'ios':
            os_name, os_version = _detect_ios_os_name_version()
            manufacturer, model = _detect_ios_manufacturer_model()
        else:
            os_name, os_version = _detect_macos_os_name_version()
            manufacturer, model = _detect_macos_manufacturer_model()

        return {
            'os_display': _build_os_display(os_name, os_version),
            'device_display': _build_device_display(manufacturer, model),
        }

    return {
        'os_display': _build_os_display(system_name or 'Unknown', _safe_text(platform.version()).strip() or 'Unknown'),
        'device_display': 'Unknown',
    }


print(json.dumps(detect_os_and_device_info(), ensure_ascii=False, indent=2))