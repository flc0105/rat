# retrieves and displays system information
import socket
import winreg

import psutil
import tabulate
import win32com.client
import wmi

from common.util import format_dict, get_size

computer = wmi.WMI()


def get_registry_value(key, subkey, value_name):
    try:
        with winreg.OpenKey(key, subkey) as reg_key:
            value, _ = winreg.QueryValueEx(reg_key, value_name)
            return value
    except FileNotFoundError:
        return None


def get_display_version():
    key = winreg.HKEY_LOCAL_MACHINE
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    return get_registry_value(key, subkey, "DisplayVersion")


def get_product_name():
    key = winreg.HKEY_LOCAL_MACHINE
    subkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    return get_registry_value(key, subkey, "ProductName")


def get_wmi_object(class_name, properties):
    objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    objSWbemServices = objWMIService.ConnectServer(".", "root\cimv2")
    colItems = objSWbemServices.ExecQuery(f"SELECT {', '.join(properties)} FROM {class_name}")
    return colItems


def get_product():
    class_name = "Win32_OperatingSystem"
    properties = ["Caption"]
    wmi_objects = get_wmi_object(class_name, properties)

    for obj in wmi_objects:
        for prop in obj.Properties_:
            return prop.Value


computer_info = computer.Win32_ComputerSystem()[0]
gpu_info = computer.Win32_VideoController()[0]
proc_info = computer.Win32_Processor()[0]
info = {'hostname': socket.gethostname(),
        'manufacturer': computer_info.Manufacturer,
        'model': computer_info.Model,
        'ram': str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + ' GB',
        'graphic_card': gpu_info.name,
        'edition': get_product(),
        'version': get_display_version()}

print(f"System\n{format_dict(info)}\n")

svmem = psutil.virtual_memory()
meminfo = {
    "total": get_size(svmem.total),
    "available": get_size(svmem.available),
    "used": get_size(svmem.used),
    "percentage": f"{svmem.percent} %"
}
print(f"RAM\n{format_dict(meminfo)}\n")

cpuinfo = {
    'processor': proc_info.Name,
    "physical_cores": psutil.cpu_count(logical=False),
    "total_cores": psutil.cpu_count(logical=True),
    'max_frequency': f'{psutil.cpu_freq().max:.2f} Mhz',
    "cpu_usage": f"{psutil.cpu_percent()}%",
}
print(f"CPU\n{format_dict(cpuinfo)}\n")

print("Partitions and Usage")
partitions = []
for partition in psutil.disk_partitions():
    mountpoint = partition.mountpoint
    fstype = partition.fstype
    opts = partition.opts
    info = [mountpoint, fstype, opts]
    try:
        partition_usage = psutil.disk_usage(partition.mountpoint)
    except PermissionError:
        continue
    total = get_size(partition_usage.total)
    used = get_size(partition_usage.used)
    free = get_size(partition_usage.free)
    percent = f'{partition_usage.percent} %'
    info.extend([total, used, free, percent])
    partitions.append(info)

print(tabulate.tabulate(partitions,
                        headers=['Mount point', 'File system type', 'Opts', 'Total Size', 'Used', 'Free', 'Percentage'],
                        tablefmt='pretty'))

print("Physical Drives")
drives = []
for disk in wmi.WMI().Win32_DiskDrive():
    model = disk.Model
    sn = disk.SerialNumber
    size = get_size(int(disk.Size))
    deviceid = disk.DeviceID
    interface_type = disk.InterfaceType
    drives.append([model, sn, size, deviceid, interface_type])

print(tabulate.tabulate(drives,
                        headers=['Model', 'Serial Number', 'Size', 'Device ID', 'Interface Type'],
                        tablefmt='pretty'))
