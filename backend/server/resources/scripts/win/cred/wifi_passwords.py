SCRIPT_METADATA = {
    "name": "windows/recon/wifi_passwords",
    "display_name": "Dump WiFi Passwords",
    "description": "Retrieve saved WiFi profiles and their passwords from the system",
    "platforms": ["windows"],
    "category": "Recon",
    "params": []
}

import subprocess
import re
import json


def get_wifi_passwords():
    result = []
    
    # 获取所有 WiFi 配置文件
    profiles_output = subprocess.run(
        ['netsh', 'wlan', 'show', 'profiles'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )
    
    # 提取所有配置文件名
    profile_pattern = r':\s*(.+)$'
    profiles = re.findall(profile_pattern, profiles_output.stdout, re.MULTILINE)
    
    for profile in profiles:
        profile = profile.strip()
        if not profile:
            continue
            
        # 获取该配置文件的详细信息
        profile_output = subprocess.run(
            ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        # 同时匹配中英文的密码字段
        password_pattern = r'(?:关键内容|Key Content)\s*:\s*(.+)$'
        password_match = re.search(password_pattern, profile_output.stdout, re.MULTILINE | re.IGNORECASE)
        
        password = password_match.group(1).strip() if password_match else ''
        
        result.append({
            'name': profile,
            'password': password
        })
    
    return result


# 执行并输出 JSON
passwords = get_wifi_passwords()
print(json.dumps(passwords, indent=2, ensure_ascii=False))