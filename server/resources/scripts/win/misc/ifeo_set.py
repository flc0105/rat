SCRIPT_METADATA = {
    "name": "windows/system/ifeo_intercept",
    "display_name": "Manage IFEO Intercept",
    "description": "Register or remove an IFEO execution intercept for a target application",
    "platforms": ["windows"],
    "category": "System",
    "params": [
        {
            "name": "action",
            "type": "select",
            "required": True,
            "default": "register",
            "options": ["register", "remove"],
            "description": "Action to perform"
        },
        {
            "name": "intercept",
            "type": "string",
            "required": True,
            "default": "",
            "description": "Target executable name to intercept"
        },
        {
            "name": "launch",
            "type": "string",
            "required": False,
            "default": "",
            "description": "Program path to launch when registering the intercept"
        }
    ]
}

import ctypes
import winreg


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_reg_path(intercept_target):
    return (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}"
        .format(intercept_target)
    )


def register_intercept(intercept_target, launch_path):
    try:
        if not intercept_target:
            print("[-] Missing intercepted target executable name")
            return

        if not launch_path:
            print("[-] Missing program path to launch")
            return

        if not is_admin():
            print("[-] Administrator privileges are required")
            return

        reg_path = get_reg_path(intercept_target)

        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, launch_path)

        print("[+] IFEO intercept registered successfully")
        print("[+] Intercepted target: {}".format(intercept_target))
        print("[+] Launch path: {}".format(launch_path))

    except Exception as error:
        print("[-] Failed to register intercept: {}".format(error))


def remove_intercept(intercept_target):
    try:
        if not intercept_target:
            print("[-] Missing intercepted target executable name")
            return

        if not is_admin():
            print("[-] Administrator privileges are required")
            return

        reg_path = get_reg_path(intercept_target)

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                reg_path,
                0,
                winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, "Debugger")
                    print("[+] Debugger value removed")
                except FileNotFoundError:
                    print("[!] Debugger value not found")

            print("[+] IFEO intercept removed successfully")
            print("[+] Target restored: {}".format(intercept_target))

        except FileNotFoundError:
            print("[!] Registry key not found (already clean)")

    except Exception as error:
        print("[-] Failed to remove intercept: {}".format(error))


action = (kwargs.get("action", "register") or "register").strip().lower()
intercept_target = (kwargs.get("intercept", "") or "").strip()
launch_path = (kwargs.get("launch", "") or "").strip()

if action == "register":
    register_intercept(intercept_target, launch_path)
elif action == "remove":
    remove_intercept(intercept_target)
else:
    print("[-] Unsupported action: {}".format(action))