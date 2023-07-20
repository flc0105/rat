import psutil
import tabulate

processes = []
for proc in psutil.process_iter():
    try:
        process = [proc.pid, proc.name(), proc.exe()]
        processes.append(process)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
print(tabulate.tabulate(processes, headers=['PID', 'Name', 'Executable path']))
