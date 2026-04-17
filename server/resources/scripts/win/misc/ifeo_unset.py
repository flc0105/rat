import ctypes
import json
import winreg


SCRIPT_METADATA = {
    "name": "windows/system/ifeo_intercept",
    "display_name": "Manage IFEO Intercept",
    "description": "Register, remove, or inspect IFEO execution intercepts",
    "platforms": ["windows"],
    "category": "System",
    "params": [
        {
            "name": "action",
            "type": "select",
            "required": True,
            "default": "register",
            "options": ["register", "remove", "list"],
            "description": "Action to perform"
        },
        {
            "name": "intercept",
            "type": "string",
            "required": False,
            "default": "",
            "description": "Target executable name"
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


IFEO_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_reg_path(intercept_target):
    return r"{}\{}".format(IFEO_ROOT, intercept_target)


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


def safe_query_value(key, value_name):
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except (FileNotFoundError, OSError):
        return None


def list_intercepts():
    result = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO_ROOT, 0, winreg.KEY_READ) as root_key:
            subkey_count = winreg.QueryInfoKey(root_key)[0]

            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(root_key, i)
                    with winreg.OpenKey(root_key, subkey_name, 0, winreg.KEY_READ) as subkey:
                        debugger = safe_query_value(subkey, "Debugger")
                        if not debugger:
                            continue

                        result.append({
                            "target": subkey_name,
                            "launch": str(debugger).strip()
                        })
                except OSError:
                    continue

        result.sort(key=lambda x: (x.get("target") or "").lower())
        print(json.dumps(result, indent=2, ensure_ascii=False))

    except FileNotFoundError:
        print("[]")
    except Exception as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False))


action = (kwargs.get("action", "register") or "register").strip().lower()
intercept_target = (kwargs.get("intercept", "") or "").strip()
launch_path = (kwargs.get("launch", "") or "").strip()

if action == "register":
    register_intercept(intercept_target, launch_path)
elif action == "remove":
    remove_intercept(intercept_target)
elif action == "list":
    list_intercepts()
else:
    print("[-] Unsupported action: {}".format(action))