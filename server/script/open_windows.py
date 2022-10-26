import pyautogui

for window in pyautogui.getAllWindows():
    if window.title:
        print(window.title)
