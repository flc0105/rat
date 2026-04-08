import json
import re
import subprocess


def get_battery_status():
    """获取电池状态，返回 JSON 格式"""
    try:
        # 获取电池信息
        result = subprocess.run(['pmset', '-g', 'batt'], capture_output=True, text=True)
        if result.returncode != 0:
            return {'error': 'No battery found or battery not available'}

        batt_output = result.stdout.strip()

        battery_info = {}

        # 获取电量百分比
        match = re.search(r'(\d+)%', batt_output)
        if match:
            battery_info['percentage'] = f"{match.group(1)}%"

        # 获取电源状态
        if 'AC Power' in batt_output:
            battery_info['state'] = 'charging'
        elif 'Battery Power' in batt_output:
            battery_info['state'] = 'discharging'

        # 获取剩余时间
        if 'Battery Power' in batt_output:
            match = re.search(r'(\d+):(\d+) remaining', batt_output)
            if match:
                battery_info['remaining_minutes'] = int(match.group(1)) * 60 + int(match.group(2))

        # 获取循环次数
        result = subprocess.run(['system_profiler', 'SPPowerDataType'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Cycle Count' in line:
                    match = re.search(r'Cycle Count:\s*(\d+)', line)
                    if match:
                        battery_info['cycle_count'] = int(match.group(1))
                elif 'Health Information' in line:
                    match = re.search(r'Health Information:\s*(.+)', line)
                    if match:
                        battery_info['health'] = match.group(1).strip()
                elif 'Condition' in line:
                    match = re.search(r'Condition:\s*(.+)', line)
                    if match:
                        battery_info['condition'] = match.group(1).strip()

        return battery_info

    except Exception as e:
        return {'error': str(e)}


result = get_battery_status()
print(json.dumps(result, ensure_ascii=False, indent=2))
