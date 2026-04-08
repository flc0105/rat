#!/usr/bin/env python3
import json
import re
import subprocess

result = {
    "current_network": None,
    "known_networks": []
}


def get_current_wifi():
    # 获取当前WiFi
    try:
        output = subprocess.check_output(['networksetup', '-getairportnetwork', 'en0'], text=True)
        if 'Current Wi-Fi Network:' in output:
            result["current_network"] = output.split(':')[1].strip()
    except:
        try:
            output = subprocess.check_output(['networksetup', '-getairportnetwork', 'en1'], text=True)
            if 'Current Wi-Fi Network:' in output:
                result["current_network"] = output.split(':')[1].strip()
        except:
            result["current_network"] = "未连接或无法获取"

    # return result


def get_wifi_history():
    # 使用系统命令获取保存的WiFi列表
    try:
        # 获取所有网络接口
        interfaces = subprocess.check_output(['networksetup', '-listallhardwareports'], text=True)

        # 查找WiFi接口
        wifi_interface = None
        lines = interfaces.split('\n')
        for i, line in enumerate(lines):
            if 'AirPort' in line or 'Wi-Fi' in line:
                if i + 1 < len(lines) and 'Device:' in lines[i + 1]:
                    wifi_interface = lines[i + 1].split(':')[1].strip()
                    break

        if wifi_interface:
            # 获取首选网络列表
            output = subprocess.check_output(['networksetup', '-listpreferredwirelessnetworks', wifi_interface],
                                             text=True)
            lines = output.split('\n')[1:]  # 跳过第一行标题
            for line in lines:
                if line.strip():
                    result["known_networks"].append(line.strip())
    except:
        pass

    # 如果上面失败，尝试另一种方法
    if not result["known_networks"]:
        try:
            output = subprocess.check_output(
                ['defaults', 'read', '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences'],
                text=True, stderr=subprocess.DEVNULL)
            ssids = re.findall(r'SSIDString = "([^"]+)"', output)
            result["known_networks"] = list(set(ssids))
        except:
            pass

    # return result


get_current_wifi()
get_wifi_history()
print(json.dumps(result, indent=2, ensure_ascii=False))
