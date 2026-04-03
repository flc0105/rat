import ctypes
import threading

# ===== 常量映射 =====
BUTTONS = {
    'ok': 0x00000000,
    'okcancel': 0x00000001,
    'yesno': 0x00000004,
    'retrycancel': 0x00000005,
}

ICONS = {
    'none': 0x00000000,
    'error': 0x00000010,
    'question': 0x00000020,
    'warning': 0x00000030,
    'info': 0x00000040,
}

RESULTS = {
    1: 'ok',
    2: 'cancel',
    3: 'abort',
    4: 'retry',
    5: 'ignore',
    6: 'yes',
    7: 'no'
}

MB_TOPMOST = 0x00040000


def show_message(title='', text='', buttons='ok', icon='none', async_show=True, topmost=False):
    btn_flag = BUTTONS.get(buttons.lower(), 0)
    icon_flag = ICONS.get(icon.lower(), 0)

    flags = btn_flag | icon_flag

    if topmost:
        flags |= MB_TOPMOST

    def _show():
        ret = ctypes.windll.user32.MessageBoxW(None, text, title, flags)
        result = RESULTS.get(ret, ret)
        print(result, flush=True)

    if async_show:
        threading.Thread(target=_show, daemon=True).start()
    else:
        _show()


title = kwargs.get('title', '')
text = kwargs.get('text', '')
icon = kwargs.get('icon', 'none')
buttons = kwargs.get('buttons', 'ok')
topmost = kwargs.get('topmost', False)

show_message(title, text, buttons, icon, topmost=topmost)
