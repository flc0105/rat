import ctypes
import threading

threading.Thread(target=ctypes.windll.user32.MessageBoxW, args=(None, text, caption, 0), daemon=True).start()
