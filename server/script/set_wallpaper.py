import ctypes
import os

filename = os.path.abspath(filename)
if os.path.isfile(filename):
    ctypes.windll.user32.SystemParametersInfoW(20, 0, filename, 0)
else:
    raise Exception('File does not exist: {}'.format(filename))