#!/usr/bin/env python3
import subprocess
import platform


def main():
    is_vm = False
    vm_type = None

    # 检查系统型号
    result = subprocess.run(['sysctl', '-n', 'hw.model'], capture_output=True, text=True)
    model = result.stdout.strip().lower()
    if 'vmware' in model or 'virtualbox' in model:
        is_vm = True
        vm_type = 'Virtual Machine'

    # 检查主板
    result = subprocess.run(['system_profiler', 'SPHardwareDataType'], capture_output=True, text=True)
    if 'VirtualBox' in result.stdout or 'VMware' in result.stdout:
        is_vm = True
        if 'VirtualBox' in result.stdout:
            vm_type = 'VirtualBox'
        elif 'VMware' in result.stdout:
            vm_type = 'VMware'

    # macOS 特定的 VM 检测
    if not is_vm:
        result = subprocess.run(['sysctl', '-n', 'kern.hv_vmm_present'], capture_output=True, text=True)
        if result.stdout.strip() == '1':
            is_vm = True
            vm_type = 'macOS Virtualization Framework'

    if is_vm:
        print(f"Running in virtual machine: {vm_type or 'Unknown'}")
    else:
        print("Running on physical hardware")


if __name__ == '__main__':
    main()