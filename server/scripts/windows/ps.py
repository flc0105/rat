# lists all active processes (ps --fmt json)
import json
import os

import psutil
import tabulate
import win32api


def get_file_description(exec_path):
    try:
        language, codepage = win32api.GetFileVersionInfo(exec_path, '\\VarFileInfo\\Translation')[0]
        string_file_info = u'\\StringFileInfo\\%04X%04X\\%s' % (language, codepage, "FileDescription")
        description = win32api.GetFileVersionInfo(exec_path, string_file_info)
        if not description.strip():
            raise
    except:
        description = os.path.basename(exec_path)
    return description


def ps():
    processes = []
    for proc in psutil.process_iter():
        try:
            process = [proc.pid, proc.name(), proc.exe()]
            processes.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    print(tabulate.tabulate(processes, headers=['PID', 'Name', 'Executable path']))


def ps_json():
    processes = []
    for proc in psutil.process_iter():
        try:
            process = {"pid": proc.pid, "name": proc.name(), "exec_path": proc.exe(), "cmd_line": proc.cmdline(),
                       "description": get_file_description(proc.exe())}
            processes.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    print(json.dumps(processes, indent=2, ensure_ascii=False))


try:
    if fmt == 'json':
        ps_json()
    else:
        raise Exception
except:
    ps()
