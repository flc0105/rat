#!/usr/bin/env python3
"""
usb-list - 列出USB设备
用法: usb-list
      usb-list --json   # JSON格式输出
      usb-list --tree   # 树形显示
"""

import sys
import json
import platform
import subprocess


def list_usb_macos():
    """macOS列出USB设备"""
    try:
        result = subprocess.run(
            ['system_profiler', 'SPUSBDataType'],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"错误: {e}"


def list_usb_linux():
    """Linux列出USB设备"""
    try:
        # 使用 lsusb
        result = subprocess.run(['lsusb'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')

        # 获取详细信息
        devices = []
        for line in lines:
            if line:
                parts = line.split(' ', 5)
                if len(parts) >= 6:
                    bus = parts[0]
                    device = parts[1]
                    vid_pid = parts[3] if len(parts) > 3 else ''
                    name = parts[5] if len(parts) > 5 else ''

                    devices.append({
                        'bus': bus,
                        'device': device,
                        'vid_pid': vid_pid,
                        'name': name
                    })
        return devices
    except FileNotFoundError:
        return "需要安装 usbutils: sudo apt install usbutils"


def parse_macos_output(output):
    """解析macOS system_profiler输出"""
    devices = []
    current = {}

    for line in output.split('\n'):
        line = line.rstrip()
        if line.startswith('    '):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                if key == 'Product ID':
                    current['product_id'] = value
                elif key == 'Vendor ID':
                    current['vendor_id'] = value
                elif key == 'Product Name':
                    current['name'] = value
                elif key == 'Speed':
                    current['speed'] = value
                elif key == 'Location ID':
                    current['location'] = value
        elif line and not line.startswith(' '):
            if current and current.get('name'):
                devices.append(current)
            current = {'name': line.strip()}

    if current and current.get('name'):
        devices.append(current)

    return devices


def print_tree(devices, indent=0):
    """树形显示"""
    for dev in devices:
        if isinstance(dev, dict):
            name = dev.get('name', 'Unknown')
            if 'speed' in dev:
                print(f"{'  ' * indent}├─ {name} ({dev.get('speed', '')})")
            else:
                print(f"{'  ' * indent}├─ {name}")
        elif isinstance(dev, str):
            print(f"{'  ' * indent}├─ {dev}")
        elif isinstance(dev, list):
            print_tree(dev, indent + 1)


def main():
    json_output = '--json' in sys.argv
    tree_output = '--tree' in sys.argv

    system = platform.system()

    if system == 'Darwin':
        output = list_usb_macos()
        devices = parse_macos_output(output)

        if json_output:
            print(json.dumps(devices, indent=2))
        elif tree_output:
            print_tree(devices)
        else:
            for dev in devices:
                name = dev.get('name', 'Unknown')
                vid = dev.get('vendor_id', '')
                pid = dev.get('product_id', '')
                if vid and pid:
                    print(f"{name} ({vid} / {pid})")
                else:
                    print(name)

    elif system == 'Linux':
        devices = list_usb_linux()

        if isinstance(devices, str):
            print(devices)
        elif json_output:
            print(json.dumps(devices, indent=2))
        elif tree_output:
            print_tree(devices)
        else:
            for dev in devices:
                print(f"{dev['bus']} {dev['device']}: {dev['name']} ({dev['vid_pid']})")

    else:
        print(f"{system} 暂不支持")
        sys.exit(1)


if __name__ == "__main__":
    main()