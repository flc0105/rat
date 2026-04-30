import os
import platform
import struct


class PsutilProcessProvider:
    """
    Pure Python / psutil process provider.

    约束：
    - 不调用 ps / tasklist / wmic / powershell / shell
    - 使用 psutil 枚举进程
    - Windows owner 为空时，用进程 token 反查用户
    - executable 只返回可执行文件名，不返回完整路径
    - macOS Universal Binary 只返回一个 arch，不返回 x86_64,arm64 这种组合
    """

    def collect(self):
        try:
            import psutil
        except Exception as e:
            raise RuntimeError('psutil is required: {}'.format(e))

        rows = []

        for proc in psutil.process_iter([
            'pid',
            'ppid',
            'name',
            'username',
            'exe',
        ]):
            try:
                row = self._build_row(proc)
            except psutil.NoSuchProcess:
                continue
            except psutil.ZombieProcess:
                continue
            except Exception:
                continue

            if row:
                rows.append(row)

        if not rows:
            raise RuntimeError('psutil returned no processes')

        return rows

    def _build_row(self, proc):
        info = self._safe_proc_info(proc)

        pid = self._safe_int(info.get('pid'), 0)
        if pid < 0:
            return None

        ppid = info.get('ppid')
        if ppid is None:
            ppid = self._safe_proc_value(proc.ppid, '')

        process_name = self._safe_text(info.get('name'))
        exe_path = self._safe_text(info.get('exe'))

        if not process_name:
            process_name = self._safe_proc_value(proc.name, '') or ''

        executable = self._basename(exe_path) or process_name

        owner = self._safe_text(info.get('username'))
        if not owner:
            owner = self._safe_proc_value(proc.username, '') or ''

        if not owner and os.name == 'nt':
            owner = self._get_windows_process_owner(pid)

        arch = self._detect_process_arch(pid, exe_path)

        return {
            'pid': pid,
            'ppid': self._normalize_int_or_empty(ppid),
            'owner': self._safe_text(owner),
            'arch': self._safe_text(arch),
            'executable': self._safe_text(executable),

            # service 层筛选用，最终输出前删除
            '_name': process_name,
            '_exe_path': exe_path,
        }

    def _safe_proc_info(self, proc):
        try:
            return proc.info or {}
        except Exception:
            return {}

    def _safe_proc_value(self, getter, default=None):
        try:
            return getter()
        except Exception:
            return default

    def _safe_text(self, value):
        if value is None:
            return ''
        return str(value).strip()

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except Exception:
            return default

    def _normalize_int_or_empty(self, value):
        if value in (None, ''):
            return ''

        try:
            return int(value)
        except Exception:
            return ''

    def _basename(self, path):
        text = self._safe_text(path)

        if not text:
            return ''

        normalized = text.replace('\\', '/').rstrip('/')

        if not normalized:
            return ''

        return normalized.rsplit('/', 1)[-1]

    # ------------------------------------------------------------------
    # Windows owner fallback
    # ------------------------------------------------------------------

    def _get_windows_process_owner(self, pid):
        """
        Windows 下 psutil.username() 为空时，直接读取进程 token 用户。

        不调用 shell。
        不调用 wmic。
        不调用 powershell。
        """
        if os.name != 'nt':
            return ''

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            TOKEN_QUERY = 0x0008
            TOKEN_USER = 1

            class SID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ('Sid', wintypes.LPVOID),
                    ('Attributes', wintypes.DWORD),
                ]

            class TOKEN_USER_STRUCT(ctypes.Structure):
                _fields_ = [
                    ('User', SID_AND_ATTRIBUTES),
                ]

            process_handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                int(pid),
            )

            if not process_handle:
                return ''

            token_handle = wintypes.HANDLE()

            try:
                if not advapi32.OpenProcessToken(
                    process_handle,
                    TOKEN_QUERY,
                    ctypes.byref(token_handle),
                ):
                    return ''

                needed = wintypes.DWORD(0)

                advapi32.GetTokenInformation(
                    token_handle,
                    TOKEN_USER,
                    None,
                    0,
                    ctypes.byref(needed),
                )

                if not needed.value:
                    return ''

                buffer = ctypes.create_string_buffer(needed.value)

                if not advapi32.GetTokenInformation(
                    token_handle,
                    TOKEN_USER,
                    buffer,
                    needed,
                    ctypes.byref(needed),
                ):
                    return ''

                token_user = ctypes.cast(
                    buffer,
                    ctypes.POINTER(TOKEN_USER_STRUCT),
                ).contents

                sid = token_user.User.Sid

                name_size = wintypes.DWORD(0)
                domain_size = wintypes.DWORD(0)
                sid_type = wintypes.DWORD(0)

                advapi32.LookupAccountSidW(
                    None,
                    sid,
                    None,
                    ctypes.byref(name_size),
                    None,
                    ctypes.byref(domain_size),
                    ctypes.byref(sid_type),
                )

                if not name_size.value:
                    return ''

                name_buffer = ctypes.create_unicode_buffer(name_size.value)
                domain_buffer = ctypes.create_unicode_buffer(domain_size.value)

                if not advapi32.LookupAccountSidW(
                    None,
                    sid,
                    name_buffer,
                    ctypes.byref(name_size),
                    domain_buffer,
                    ctypes.byref(domain_size),
                    ctypes.byref(sid_type),
                ):
                    return ''

                name = name_buffer.value
                domain = domain_buffer.value

                if domain and name:
                    return '{}\\{}'.format(domain, name)

                return name or domain or ''

            finally:
                if token_handle:
                    kernel32.CloseHandle(token_handle)
                kernel32.CloseHandle(process_handle)

        except Exception:
            return ''

    # ------------------------------------------------------------------
    # arch detection
    # ------------------------------------------------------------------

    def _detect_process_arch(self, pid, executable):
        if os.name == 'nt':
            arch = self._detect_windows_process_arch(pid)
            if arch:
                return arch

        arch = self._detect_executable_arch(executable)
        if arch:
            return arch

        return ''

    def _detect_windows_process_arch(self, pid):
        """
        Windows:
        - 优先 IsWow64Process2
        - 其次 IsWow64Process
        """
        if os.name != 'nt':
            return ''

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                int(pid),
            )

            if not handle:
                return ''

            try:
                is_wow64_process2 = getattr(kernel32, 'IsWow64Process2', None)

                if is_wow64_process2 is not None:
                    process_machine = wintypes.USHORT()
                    native_machine = wintypes.USHORT()

                    ok = is_wow64_process2(
                        handle,
                        ctypes.byref(process_machine),
                        ctypes.byref(native_machine),
                    )

                    if ok:
                        process_value = int(process_machine.value)
                        native_value = int(native_machine.value)

                        if process_value:
                            return self._windows_machine_to_arch(process_value)

                        return self._windows_machine_to_arch(native_value)

                is_wow64_process = getattr(kernel32, 'IsWow64Process', None)

                if is_wow64_process is not None:
                    is_wow64 = wintypes.BOOL(False)

                    ok = is_wow64_process(
                        handle,
                        ctypes.byref(is_wow64),
                    )

                    if ok and bool(is_wow64.value):
                        return 'x86'

                    return self._normalize_machine_name(platform.machine())

            finally:
                kernel32.CloseHandle(handle)

        except Exception:
            return ''

        return ''

    def _windows_machine_to_arch(self, machine):
        mapping = {
            0x014c: 'x86',
            0x8664: 'x86_64',
            0x01c0: 'arm',
            0x01c4: 'armv7',
            0xaa64: 'arm64',
        }

        return mapping.get(int(machine), '')

    def _detect_executable_arch(self, executable):
        path = self._safe_text(executable)

        if not path:
            return ''

        if not os.path.exists(path):
            return ''

        try:
            with open(path, 'rb') as file_obj:
                header = file_obj.read(4096)
        except Exception:
            return ''

        if len(header) < 4:
            return ''

        arch = self._detect_elf_arch(header)
        if arch:
            return arch

        arch = self._detect_macho_arch(header)
        if arch:
            return arch

        arch = self._detect_pe_arch(path, header)
        if arch:
            return arch

        return ''

    def _detect_elf_arch(self, data):
        if not data.startswith(b'\x7fELF'):
            return ''

        if len(data) < 20:
            return ''

        elf_class = data[4]
        endian_flag = data[5]

        if endian_flag == 1:
            endian = '<'
        elif endian_flag == 2:
            endian = '>'
        else:
            return ''

        try:
            machine = struct.unpack(endian + 'H', data[18:20])[0]
        except Exception:
            return ''

        mapping = {
            0x03: 'x86',
            0x08: 'mips',
            0x14: 'ppc',
            0x28: 'arm',
            0x2a: 'superh',
            0x32: 'ia64',
            0x3e: 'x86_64',
            0xb7: 'aarch64',
            0xf3: 'riscv',
        }

        arch = mapping.get(machine, '')

        if arch == 'riscv' and elf_class == 2:
            return 'riscv64'

        return arch

    def _detect_macho_arch(self, data):
        if len(data) < 8:
            return ''

        magic = data[:4]

        if magic in (
            b'\xfe\xed\xfa\xce',
            b'\xfe\xed\xfa\xcf',
            b'\xce\xfa\xed\xfe',
            b'\xcf\xfa\xed\xfe',
        ):
            return self._detect_thin_macho_arch(data)

        if magic in (
            b'\xca\xfe\xba\xbe',
            b'\xca\xfe\xba\xbf',
            b'\xbe\xba\xfe\xca',
            b'\xbf\xba\xfe\xca',
        ):
            return self._detect_fat_macho_arch(data)

        return ''

    def _detect_thin_macho_arch(self, data):
        magic = data[:4]

        if magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
            endian = '>'
        elif magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            endian = '<'
        else:
            return ''

        if len(data) < 8:
            return ''

        try:
            cputype = struct.unpack(endian + 'I', data[4:8])[0]
        except Exception:
            return ''

        return self._macho_cputype_to_arch(cputype)

    def _detect_fat_macho_arch(self, data):
        """
        Universal / Fat Mach-O。

        旧逻辑如果返回 x86_64,arm64，会让 ps 表格看起来像一个进程有两个架构。
        这里改成只返回一个：
        - 如果 fat binary 包含当前机器原生 arch，优先返回原生 arch
        - 否则返回第一个可识别 arch

        注意：
        这表示 executable 的优先架构，不保证能精确判断 Rosetta 下某个进程实际选择的 slice。
        """
        magic = data[:4]

        if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
            endian = '>'
        elif magic in (b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'):
            endian = '<'
        else:
            return ''

        is_64 = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')

        if len(data) < 8:
            return ''

        try:
            count = struct.unpack(endian + 'I', data[4:8])[0]
        except Exception:
            return ''

        archs = []
        offset = 8
        entry_size = 32 if is_64 else 20

        for _ in range(min(count, 16)):
            if len(data) < offset + entry_size:
                break

            try:
                cputype = struct.unpack(
                    endian + 'I',
                    data[offset:offset + 4],
                )[0]
            except Exception:
                break

            arch = self._macho_cputype_to_arch(cputype)

            if arch and arch not in archs:
                archs.append(arch)

            offset += entry_size

        if not archs:
            return ''

        native_arch = self._normalize_machine_name(platform.machine())

        if native_arch in archs:
            return native_arch

        return archs[0]

    def _macho_cputype_to_arch(self, cputype):
        CPU_ARCH_ABI64 = 0x01000000

        base = int(cputype) & ~CPU_ARCH_ABI64
        is_64 = bool(int(cputype) & CPU_ARCH_ABI64)

        if base == 7:
            return 'x86_64' if is_64 else 'x86'

        if base == 12:
            return 'arm64' if is_64 else 'arm'

        if base == 18:
            return 'ppc64' if is_64 else 'ppc'

        return ''

    def _detect_pe_arch(self, path, data):
        if len(data) < 0x40:
            return ''

        if data[:2] != b'MZ':
            return ''

        try:
            pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
        except Exception:
            return ''

        try:
            with open(path, 'rb') as file_obj:
                file_obj.seek(pe_offset)
                pe_header = file_obj.read(6)
        except Exception:
            return ''

        if len(pe_header) < 6:
            return ''

        if pe_header[:4] != b'PE\x00\x00':
            return ''

        try:
            machine = struct.unpack('<H', pe_header[4:6])[0]
        except Exception:
            return ''

        return self._windows_machine_to_arch(machine)

    def _normalize_machine_name(self, value):
        text = self._safe_text(value).lower()

        mapping = {
            'amd64': 'x86_64',
            'x86_64': 'x86_64',
            'i386': 'x86',
            'i686': 'x86',
            'x86': 'x86',
            'arm64': 'arm64',
            'aarch64': 'arm64',
            'arm': 'arm',
        }

        return mapping.get(text, text)