# !/usr/bin/env python3
import json
import re
import subprocess


def get_usb_history():
    result = {
        "current_usb_devices": [],
        "recent_usb_devices": []
    }

    # 1. 获取当前连接的USB设备
    try:
        output = subprocess.check_output(['system_profiler', 'SPUSBDataType', '-json'], text=True)
        usb_data = json.loads(output)

        if 'SPUSBDataType' in usb_data:
            def extract_devices(device_list):
                devices = []
                for device in device_list:
                    if '_name' in device and device['_name']:
                        device_info = {
                            "name": device.get('_name', 'Unknown'),
                            "vendor": device.get('manufacturer', 'Unknown'),
                            "serial": device.get('serial_num', ''),
                            "speed": device.get('speed', ''),
                            "bus_power": device.get('bus_power', ''),
                            "location": device.get('location_id', '')
                        }
                        devices.append(device_info)

                    if '_items' in device:
                        devices.extend(extract_devices(device['_items']))
                return devices

            result["current_usb_devices"] = extract_devices(usb_data['SPUSBDataType'])
    except Exception as e:
        result["current_usb_error"] = str(e)

    # 2. 获取最近连接的USB设备（从系统日志）
    try:
        # 获取最近24小时的USB连接日志
        log_output = subprocess.check_output(
            ['log', 'show', '--predicate', 'subsystem == "com.apple.IOUSBHost"', '--last', '24h', '--info'],
            text=True, stderr=subprocess.DEVNULL
        )

        usb_devices = set()
        # 提取设备名称
        patterns = [
            r'device "([^"]+)"',
            r'AppleUSB.*device "([^"]+)"',
            r'USB device "([^"]+)"'
        ]

        for line in log_output.split('\n'):
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    device_name = match.group(1)
                    if device_name and len(device_name) < 50 and device_name != "USB Receiver":
                        usb_devices.add(device_name)

        result["recent_usb_devices"] = list(usb_devices)[:20]

        # 如果还是空的，尝试从ioreg获取历史
        if not result["recent_usb_devices"]:
            ioreg_output = subprocess.check_output(['ioreg', '-r', '-c', 'IOUSBHostDevice'], text=True)
            usb_names = re.findall(r'"USB Product Name" = "([^"]+)"', ioreg_output)
            unique_names = list(set(usb_names))
            result["recent_usb_devices"] = [n for n in unique_names if n and "Receiver" not in n][:20]

    except Exception as e:
        result["recent_usb_error"] = str(e)
        # 备用方案：从ioreg获取
        try:
            ioreg_output = subprocess.check_output(['ioreg', '-r', '-c', 'IOUSBHostDevice'], text=True)
            usb_names = re.findall(r'"USB Product Name" = "([^"]+)"', ioreg_output)
            unique_names = list(set(usb_names))
            result["recent_usb_devices"] = [n for n in unique_names if n and "Receiver" not in n][:20]
        except:
            pass

    return result


usb_info = get_usb_history()
print(json.dumps(usb_info, indent=2, ensure_ascii=False))
