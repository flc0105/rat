import os
import time

from core.platform.platform_identity import detect_platform_alias
from core.utils.formatting import get_size, seconds_to_readable_text, timestamp_to_readable_time

if detect_platform_alias() == 'ios':
    from objc_util import ObjCClass


def _safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def get_ios_username():
    for key in ('USER', 'LOGNAME', 'USERNAME'):
        value = os.environ.get(key)
        if value:
            return value
    return _safe_call(os.getlogin, 'unknown')


def get_ios_process_info():
    info = {
        'process_name': None,
        'process_id': None,
        'username': None,
        'arguments': None,
        'processor_count': None,
        'physical_memory': None,
        'system_boot_time': None,
        'system_uptime': None,
        'operating_system_version_string': None,
        'low_power_mode_enabled': None,
    }

    try:
        NSProcessInfo = ObjCClass('NSProcessInfo')
        proc = NSProcessInfo.processInfo()
        info['process_name'] = _safe_call(lambda: str(proc.processName()))
        info['process_id'] = _safe_call(lambda: int(proc.processIdentifier()))
        info['username'] = _safe_call(lambda: str(proc.userName()))
        info['arguments'] = _safe_call(lambda: [str(x) for x in list(proc.arguments())])
        info['processor_count'] = _safe_call(lambda: int(proc.processorCount()))
        physical_memory = _safe_call(lambda: int(proc.physicalMemory()))
        info['physical_memory'] = get_size(physical_memory) if physical_memory is not None else None
        system_uptime = _safe_call(lambda: int(proc.systemUptime()))
        info['system_uptime'] = seconds_to_readable_text(system_uptime) if system_uptime is not None else None
        info['system_boot_time'] = timestamp_to_readable_time(
            int(time.time() - system_uptime)) if system_uptime is not None else None
        info['operating_system_version_string'] = _safe_call(lambda: str(proc.operatingSystemVersionString()))
        info['low_power_mode_enabled'] = _safe_call(lambda: bool(proc.isLowPowerModeEnabled()))
    except Exception:
        pass

    return info


def get_ios_device_info():
    info = {
        'device_name': None,
        'device_model': None,
        'device_localized_model': None,
        'device_type': None,
        'system': None,
        'system_version': None,
        'machine_name': None,
        'hostname': None,
        'identifier_for_vendor': None,
    }

    try:
        UIDevice = ObjCClass('UIDevice')
        device = UIDevice.currentDevice()

        idiom_map = {
            0: "Phone",
            1: "Pad",
            2: "TV",
            3: "CarPlay",
            4: "Mac",
            5: "Vision",
        }

        info['device_name'] = _safe_call(lambda: str(device.name()))
        info['device_model'] = _safe_call(lambda: str(device.model()))
        info['device_localized_model'] = _safe_call(lambda: str(device.localizedModel()))
        info['system'] = _safe_call(lambda: str(device.systemName()))
        info['system_version'] = _safe_call(lambda: str(device.systemVersion()))
        info['device_type'] = _safe_call(
            lambda: idiom_map.get(int(device.userInterfaceIdiom()), str(int(device.userInterfaceIdiom()))))

        identifier_for_vendor = _safe_call(lambda: device.identifierForVendor())
        if identifier_for_vendor is not None:
            info['identifier_for_vendor'] = _safe_call(lambda: str(identifier_for_vendor.UUIDString()))
    except Exception:
        pass

    try:
        uname_info = os.uname()
        info['machine_name'] = uname_info.machine
        info['hostname'] = uname_info.nodename
    except Exception:
        pass

    return info


def get_ios_bundle_info():
    info = {
        'bundle_identifier': None,
        'bundle_path': None,
        'executable_path': None,
        'resource_path': None,
        'bundle_name': None,
        'app_name': None,
        'bundle_version': None,
        'bundle_short_version': None,
    }

    try:
        NSBundle = ObjCClass('NSBundle')
        bundle = NSBundle.mainBundle()

        info['bundle_identifier'] = _safe_call(lambda: str(bundle.bundleIdentifier()))
        info['bundle_path'] = _safe_call(lambda: str(bundle.bundlePath()))
        info['executable_path'] = _safe_call(lambda: str(bundle.executablePath()))
        info['resource_path'] = _safe_call(lambda: str(bundle.resourcePath()))

        info_dict = _safe_call(lambda: bundle.infoDictionary())
        if info_dict is not None:
            def get_value(key):
                value = info_dict.objectForKey_(key)
                return str(value) if value is not None else None

            info['bundle_name'] = _safe_call(lambda: get_value('CFBundleName'))
            info['app_name'] = _safe_call(lambda: get_value('CFBundleDisplayName')) or _safe_call(
                lambda: get_value('CFBundleName'))
            info['bundle_version'] = _safe_call(lambda: get_value('CFBundleVersion'))
            info['bundle_short_version'] = _safe_call(lambda: get_value('CFBundleShortVersionString'))
    except Exception:
        pass

    return info
