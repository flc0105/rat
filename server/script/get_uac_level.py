import winreg


def get_uac_level():
    # 打开注册表项
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 0,
                         winreg.KEY_READ)
    # 初始化变量
    i, ConsentPromptBehaviorAdmin, EnableLUA, PromptOnSecureDesktop = 0, None, None, None
    # 循环遍历注册表项中的值
    while True:
        try:
            name, data, type = winreg.EnumValue(key, i)
            # 根据值的名称来获取对应的数据
            if name == 'ConsentPromptBehaviorAdmin':
                ConsentPromptBehaviorAdmin = data
            elif name == 'EnableLUA':
                EnableLUA = data
            elif name == 'PromptOnSecureDesktop':
                PromptOnSecureDesktop = data
            i += 1
        except WindowsError:
            break
    # 根据获取到的数据返回不同的UAC级别
    if ConsentPromptBehaviorAdmin == 2 and EnableLUA == 1 and PromptOnSecureDesktop == 1:
        return '3/3 (Maximum)'
    elif ConsentPromptBehaviorAdmin == 5 and EnableLUA == 1 and PromptOnSecureDesktop == 1:
        return '2/3 (Default)'
    elif ConsentPromptBehaviorAdmin == 5 and EnableLUA == 1 and PromptOnSecureDesktop == 0:
        return '1/3'
    elif (ConsentPromptBehaviorAdmin == 0 and EnableLUA == 1 and PromptOnSecureDesktop == 0) or EnableLUA == 0:
        return '0/3 (Disabled)'
    else:
        return None


# 调用函数并打印结果
uac_level = get_uac_level()
if uac_level is not None:
    print("UAC级别:", uac_level)
else:
    print("无法确定UAC级别。")
