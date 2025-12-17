# #get keychain passwords
# import subprocess
#
#
# def keychain(args_dict):
#     """
#     提取钥匙串密码
#     keychain --dump
#     keychain --find google.com
#     """
#
#     try:
#         if args_dict.get('dump'):
#             # 导出所有钥匙串条目（需要密码）
#             result = subprocess.run(['security', 'dump-keychain'], capture_output=True, text=True)
#             return 1, result.stdout if result.stdout else "需要用户授权"
#
#         elif args_dict.get('find'):
#             # 查找特定密码
#             target = args_dict.get('find')
#             result = subprocess.run([
#                 'security', 'find-internet-password', '-g', '-s', target
#             ], capture_output=True, text=True)
#             return 1, result.stderr if result.stderr else "未找到密码"
#
#         else:
#             # 列出钥匙串内容
#             result = subprocess.run(['security', 'list-keychains'], capture_output=True, text=True)
#             keychains = result.stdout.strip()
#
#             info = ["=== 钥匙串列表 ==="]
#             for keychain in keychains.split('\n'):
#                 keychain = keychain.strip().strip('"')
#                 result = subprocess.run(['security', 'dump-keychain', keychain],
#                                         capture_output=True, text=True)
#                 if result.stdout:
#                     entries = len([line for line in result.stdout.split('\n') if '0x00000007' in line])
#                     info.append(f"{keychain}: {entries} 个密码条目")
#
#             return 1, "\n".join(info)
#
#     except Exception as e:
#         return 0, f"钥匙串操作失败: {str(e)}"
#
#
# arg = {"find": "EOSR6m2_930C94-113_Canon0A"}
# # arg={"dump": True}
# print(keychain(arg))
import subprocess


def wifipass (args_dict):
    """
    提取保存的WiFi密码
    wifipass
    wifipass --ssid MyWiFi
    """
    target_ssid = args_dict.get('ssid', '')

    try:
        # 获取所有已知网络
        result = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True, text=True)
        wifi_interface = None
        for line in result.stdout.split('\n'):
            if 'Wi-Fi' in line or 'AirPort' in line:
                wifi_interface = line.split(': ')[1] if ': ' in line else 'en0'

        if not wifi_interface:
            return 0, "未找到WiFi接口"

        # 获取已知网络列表
        result = subprocess.run(['networksetup', '-listpreferredwirelessnetworks', wifi_interface], capture_output=True,
                                text=True)
        networks = [line.strip() for line in result.stdout.split('\n')[1:] if line.strip()]

        passwords = []
        for network in networks:
            if target_ssid and target_ssid not in network:
                continue

            try:
                # 尝试获取密码
                cmd = ['security', 'find-generic-password', '-D', 'AirPort network password', '-ga', network]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if 'password:' in result.stderr:
                    password_line = [line for line in result.stderr.split('\n') if 'password:' in line]
                    if password_line:
                        password = password_line[0].split('password: ')[1].strip('"')
                        passwords.append(f"{network}: {password}")
            except:
                passwords.append(f"{network}: [需要管理员权限]")

        if passwords:
            return 1, "WiFi密码:\n" + "\n".join(passwords)
        else:
            return 1, "未找到保存的WiFi密码或需要管理员权限"

    except Exception as e:
        return 0, f"WiFi密码提取失败: {str(e)}"

# arg = {"find": "EOSR6m2_930C94-113_Canon0A"}
# arg={"dump": True}
print(wifipass({}))