# enumerates and prints the titles of all open windows
import pyautogui

for window in pyautogui.getAllWindows():
    if window.title:
        print(window.title)
