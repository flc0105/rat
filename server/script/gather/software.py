# retrieves a list of installed software
import json
import winreg


def enum_uninstall_key(reg, flag):
    software_list = []
    # 打开注册表项
    key = winreg.OpenKey(reg, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 0, winreg.KEY_READ | flag)
    # 获取注册表项中的软件信息
    for i in range(winreg.QueryInfoKey(key)[0]):
        software = {}
        try:
            # 打开子键
            subkey = winreg.OpenKey(key, winreg.EnumKey(key, i))
            # 获取软件名称
            software['Name'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
            try:
                # 获取软件版本
                software['Version'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
            except EnvironmentError:
                software['Version'] = None
            try:
                # 获取软件发布商
                software['Publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0]
            except EnvironmentError:
                software['Publisher'] = None
            try:
                # 获取安装日期
                software['InstallDate'] = winreg.QueryValueEx(subkey, 'InstallDate')[0]
            except EnvironmentError:
                software['InstallDate'] = None
            software_list.append(software)
        except EnvironmentError:
            continue
    return software_list


try:
    software_list = []
    # 遍历三个注册表项，包括32位和64位的HKEY_LOCAL_MACHINE，以及HKEY_CURRENT_USER
    for item in ((winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
                 (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                 (winreg.HKEY_CURRENT_USER, 0)):
        software_list += enum_uninstall_key(*item)
    # 按软件名称进行排序
    sorted_software_list = sorted(software_list, key=lambda s: s['Name'].lower())
    # 将列表转换为JSON格式并打印输出
    json_output = json.dumps(sorted_software_list, indent=4, ensure_ascii=False)
    print(json_output)
except Exception as exception:
    print(exception)
