SCRIPT_METADATA = {
    "name": "win/ui/task_dialog",
    "display_name": "Task Dialog",
    "description": "Show a native Windows task dialog",
    "platforms": ["windows"],
    "category": "UI",
    "params": [
        {"name": "title", "type": "string", "required": False, "default": "", "description": "Window title"},
        {"name": "main", "type": "string", "required": False, "default": "", "description": "Main instruction"},
        {"name": "text", "type": "string", "required": True, "default": "", "description": "Dialog content"},
        {"name": "icon", "type": "select", "required": False, "default": "none", "options": ["none", "warning", "error", "info", "shield"], "description": "Dialog icon"},
        {"name": "buttons", "type": "select", "required": False, "default": "ok", "options": ["ok", "okcancel", "yesno", "retrycancel"], "description": "Button layout"}
    ]
}

import ctypes
import threading

# ===== 常量 =====
TD_BUTTONS = {
    'ok': 0x0001,
    'okcancel': 0x0001 | 0x0008,
    'yesno': 0x0002 | 0x0004,
    'retrycancel': 0x0010 | 0x0008,
}

# ⭐ 正确实现
def MAKEINTRESOURCE(i):
    return ctypes.c_void_p(i & 0xFFFF)

TD_ICONS = {
    'none': None,
    'warning': MAKEINTRESOURCE(-1),  # 修正：warning 应该是 -1
    'error': MAKEINTRESOURCE(-2),    # 修正：error 应该是 -2
    'info': MAKEINTRESOURCE(-3),
    'shield': MAKEINTRESOURCE(-4),
}

RESULTS = {
    1: 'ok',
    2: 'cancel',
    4: 'retry',
    6: 'yes',
    7: 'no'
}

TaskDialog = ctypes.windll.comctl32.TaskDialog

# 可选但推荐：声明参数类型，避免 ctypes 自动推断出问题
TaskDialog.argtypes = [
    ctypes.c_void_p,                  # hwndParent
    ctypes.c_void_p,                  # hInstance
    ctypes.c_wchar_p,                 # pszWindowTitle
    ctypes.c_wchar_p,                 # pszMainInstruction
    ctypes.c_wchar_p,                 # pszContent
    ctypes.c_uint,                    # dwCommonButtons
    ctypes.c_void_p,                  # pszIcon
    ctypes.POINTER(ctypes.c_int),     # pnButton
]
TaskDialog.restype = ctypes.c_long


def show_message(title='', main='', text='',
                 buttons='ok', icon='none',
                 async_show=True):

    btn_flag = TD_BUTTONS.get(buttons.lower(), 0x0001)
    icon_flag = TD_ICONS.get(icon.lower(), None)

    def _show():
        result = ctypes.c_int()

        TaskDialog(
            None,
            None,
            title,
            main,
            text,
            btn_flag,
            icon_flag,
            ctypes.byref(result)
        )

        ret = RESULTS.get(result.value, result.value)
        print(ret, flush=True)

    if async_show:
        threading.Thread(target=_show, daemon=True).start()
    else:
        _show()


# ===== 参数 =====
title = kwargs.get('title', '')
main = kwargs.get('main', '')
text = kwargs.get('text', '')
icon = kwargs.get('icon', 'none')
buttons = kwargs.get('buttons', 'ok')

show_message(title, main, text, buttons, icon, True)