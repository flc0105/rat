#!/usr/bin/env python3
"""
wifi-scan - 扫描WiFi网络
用法: wifi-scan [--signal] [--json]
      wifi-scan           # 列出所有WiFi
      wifi-scan --signal  # 显示信号强度
      wifi-scan --json    # JSON格式输出
依赖:
  Linux: nmcli (NetworkManager)
  macOS: /System/Library/PrivateFrameworks/Apple80211.framework
"""

import sys
import subprocess
import json
import platform


def scan_macos():
    """macOS扫描WiFi"""
    try:
        result = subprocess.run(
            ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
            capture_output=True,
            text=True
        )
        return result.stdout
    except FileNotFoundError:
        print("无法扫描WiFi，请检查权限")
        return ""


def scan_linux():
    """Linux扫描WiFi（使用nmcli）"""
    try:
        # 先扫描
        subprocess.run(['nmcli', 'device', 'wifi', 'rescan'], capture_output=True)
        # 获取列表
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'SSID,SECURITY,SIGNAL', 'device', 'wifi', 'list'],
            capture_output=True,
            text=True
        )
        return result.stdout
    except FileNotFoundError:
        print("需要安装 NetworkManager: sudo apt install network-manager")
        return ""


def format_output_macos(output, show_signal=False, json_output=False):
    """格式化macOS输出"""
    lines = output.strip().split('\n')[1:]  # 跳过表头
    networks = []

    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            ssid = ' '.join(parts[:-2])
            signal = parts[-2]
            security = parts[-1]

            if json_output:
                networks.append({'ssid': ssid, 'signal': signal, 'security': security})
            else:
                if show_signal:
                    print(f"{ssid:40s} {signal:>8s} {security}")
                else:
                    print(f"{ssid:40s} {security}")

    if json_output:
        print(json.dumps(networks, indent=2))


def format_output_linux(output, show_signal=False, json_output=False):
    """格式化Linux输出"""
    lines = output.strip().split('\n')
    networks = []

    for line in lines:
        if not line:
            continue
        parts = line.split(':')
        if len(parts) >= 3:
            ssid = parts[0] or '(隐藏网络)'
            security = parts[1]
            signal = parts[2]

            if json_output:
                networks.append({'ssid': ssid, 'signal': signal, 'security': security})
            else:
                if show_signal:
                    print(f"{ssid:40s} {signal:>8s}% {security}")
                else:
                    print(f"{ssid:40s} {security}")

    if json_output:
        print(json.dumps(networks, indent=2))


def main():
    show_signal = '--signal' in sys.argv or '-s' in sys.argv
    json_output = '--json' in sys.argv or '-j' in sys.argv

    system = platform.system()

    if system == 'Darwin':
        output = scan_macos()
        if output:
            format_output_macos(output, show_signal, json_output)
    elif system == 'Linux':
        output = scan_linux()
        if output:
            format_output_linux(output, show_signal, json_output)
    else:
        print(f"{system} 暂不支持")
        sys.exit(1)


if __name__ == "__main__":
    main()