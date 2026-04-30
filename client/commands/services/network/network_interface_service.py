import ctypes
import socket

from core.platform.platform_identity import detect_platform_alias
from core.utils.command_output import StructuredCommandResult


class NetworkInterfaceService:
    """
    Network interface collection service.

    约束：
    - 不做 fallback
    - 每个平台只走一种明确方案
    - iOS / macOS / Linux: libc.getifaddrs()
    - Windows: psutil.net_if_addrs() / psutil.net_if_stats()
    """

    def __init__(self, owner=None):
        self.owner = owner

    def build_ifconfig_result(self):
        rows = self.collect_ifconfig()

        if not rows:
            raise RuntimeError('No useful network interfaces found')

        return StructuredCommandResult(
            status=1,
            data=rows,
            shape='table',
        )

    def collect_ifconfig(self):
        platform_alias = detect_platform_alias()

        if platform_alias in ('ios', 'mac', 'linux'):
            rows = self._collect_by_getifaddrs(platform_alias)
        elif platform_alias == 'win':
            rows = self._collect_windows_by_psutil()
        else:
            raise RuntimeError('Unsupported platform: {}'.format(platform_alias))

        rows = self._filter_and_sort_rows(rows)

        if not rows:
            raise RuntimeError('No useful network interfaces found')

        return rows

    # ------------------------------------------------------------------
    # iOS / macOS / Linux: getifaddrs only
    # ------------------------------------------------------------------

    def _collect_by_getifaddrs(self, platform_alias):
        libc = ctypes.CDLL(None)

        AF_INET = socket.AF_INET
        AF_LINK = 18
        AF_PACKET = 17

        class SockaddrDarwin(ctypes.Structure):
            _fields_ = [
                ('sa_len', ctypes.c_uint8),
                ('sa_family', ctypes.c_uint8),
                ('sa_data', ctypes.c_char * 14),
            ]

        class SockaddrLinux(ctypes.Structure):
            _fields_ = [
                ('sa_family', ctypes.c_ushort),
                ('sa_data', ctypes.c_char * 14),
            ]

        class SockaddrInDarwin(ctypes.Structure):
            _fields_ = [
                ('sin_len', ctypes.c_uint8),
                ('sin_family', ctypes.c_uint8),
                ('sin_port', ctypes.c_uint16),
                ('sin_addr', ctypes.c_ubyte * 4),
                ('sin_zero', ctypes.c_char * 8),
            ]

        class SockaddrInLinux(ctypes.Structure):
            _fields_ = [
                ('sin_family', ctypes.c_ushort),
                ('sin_port', ctypes.c_uint16),
                ('sin_addr', ctypes.c_ubyte * 4),
                ('sin_zero', ctypes.c_char * 8),
            ]

        class SockaddrDl(ctypes.Structure):
            """
            Darwin / iOS AF_LINK sockaddr_dl.

            MAC 地址位置：
            sdl_data[sdl_nlen : sdl_nlen + sdl_alen]
            """
            _fields_ = [
                ('sdl_len', ctypes.c_uint8),
                ('sdl_family', ctypes.c_uint8),
                ('sdl_index', ctypes.c_uint16),
                ('sdl_type', ctypes.c_uint8),
                ('sdl_nlen', ctypes.c_uint8),
                ('sdl_alen', ctypes.c_uint8),
                ('sdl_slen', ctypes.c_uint8),
                ('sdl_data', ctypes.c_ubyte * 46),
            ]

        class SockaddrLl(ctypes.Structure):
            """
            Linux AF_PACKET sockaddr_ll.
            """
            _fields_ = [
                ('sll_family', ctypes.c_ushort),
                ('sll_protocol', ctypes.c_ushort),
                ('sll_ifindex', ctypes.c_int),
                ('sll_hatype', ctypes.c_ushort),
                ('sll_pkttype', ctypes.c_ubyte),
                ('sll_halen', ctypes.c_ubyte),
                ('sll_addr', ctypes.c_ubyte * 8),
            ]

        class IfAddrs(ctypes.Structure):
            pass

        IfAddrs._fields_ = [
            ('ifa_next', ctypes.POINTER(IfAddrs)),
            ('ifa_name', ctypes.c_char_p),
            ('ifa_flags', ctypes.c_uint),
            ('ifa_addr', ctypes.c_void_p),
            ('ifa_netmask', ctypes.c_void_p),
            ('ifa_dstaddr', ctypes.c_void_p),
            ('ifa_data', ctypes.c_void_p),
        ]

        getifaddrs = libc.getifaddrs
        getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(IfAddrs))]
        getifaddrs.restype = ctypes.c_int

        freeifaddrs = libc.freeifaddrs
        freeifaddrs.argtypes = [ctypes.POINTER(IfAddrs)]
        freeifaddrs.restype = None

        addrs = ctypes.POINTER(IfAddrs)()

        if getifaddrs(ctypes.byref(addrs)) != 0:
            raise RuntimeError('getifaddrs failed')

        interfaces = {}

        try:
            p = addrs

            while p:
                item = p.contents
                name = self._decode_interface_name(item.ifa_name)

                if name and item.ifa_addr:
                    if platform_alias in ('ios', 'mac'):
                        family = int(ctypes.cast(
                            item.ifa_addr,
                            ctypes.POINTER(SockaddrDarwin),
                        ).contents.sa_family)
                    else:
                        family = int(ctypes.cast(
                            item.ifa_addr,
                            ctypes.POINTER(SockaddrLinux),
                        ).contents.sa_family)

                    entry = interfaces.setdefault(name, {
                        'name': name,
                        'ip': [],
                        'mac': '',
                    })

                    if family == AF_INET:
                        if platform_alias in ('ios', 'mac'):
                            sin = ctypes.cast(
                                item.ifa_addr,
                                ctypes.POINTER(SockaddrInDarwin),
                            ).contents
                        else:
                            sin = ctypes.cast(
                                item.ifa_addr,
                                ctypes.POINTER(SockaddrInLinux),
                            ).contents

                        ip = socket.inet_ntoa(bytes(sin.sin_addr))

                        if ip and ip not in entry['ip']:
                            entry['ip'].append(ip)

                    elif platform_alias in ('ios', 'mac') and family == AF_LINK:
                        sdl = ctypes.cast(
                            item.ifa_addr,
                            ctypes.POINTER(SockaddrDl),
                        ).contents

                        mac_bytes = bytes(sdl.sdl_data)[
                            sdl.sdl_nlen:sdl.sdl_nlen + sdl.sdl_alen
                        ]

                        mac = self._format_mac_bytes(mac_bytes)

                        if mac:
                            entry['mac'] = mac

                    elif platform_alias == 'linux' and family == AF_PACKET:
                        sll = ctypes.cast(
                            item.ifa_addr,
                            ctypes.POINTER(SockaddrLl),
                        ).contents

                        mac_bytes = bytes(sll.sll_addr[:sll.sll_halen])
                        mac = self._format_mac_bytes(mac_bytes)

                        if mac:
                            entry['mac'] = mac

                p = item.ifa_next

        finally:
            freeifaddrs(addrs)

        return list(interfaces.values())

    # ------------------------------------------------------------------
    # Windows: psutil only
    # ------------------------------------------------------------------

    def _collect_windows_by_psutil(self):
        try:
            import psutil
        except Exception as e:
            raise RuntimeError('psutil is required on Windows: {}'.format(e))

        all_addrs = psutil.net_if_addrs()
        all_stats = psutil.net_if_stats()

        if not all_addrs:
            raise RuntimeError('psutil returned no network interfaces')

        rows = []

        for name, addrs in all_addrs.items():
            stats = all_stats.get(name)

            if stats is not None and not getattr(stats, 'isup', False):
                continue

            item = {
                'name': name,
                'ip': [],
                'mac': '',
            }

            for addr in addrs or []:
                family = getattr(addr, 'family', None)
                address = str(getattr(addr, 'address', '') or '').strip()

                if not address:
                    continue

                if self._is_ipv4_family(family):
                    if address not in item['ip']:
                        item['ip'].append(address)
                    continue

                if self._is_psutil_mac_family(family, psutil):
                    mac = self._normalize_mac(address)
                    if mac:
                        item['mac'] = mac

            rows.append(item)

        return rows

    # ------------------------------------------------------------------
    # Filtering / formatting
    # ------------------------------------------------------------------

    def _filter_and_sort_rows(self, rows):
        result = []
        seen = set()

        for row in rows:
            name = str(row.get('name') or '').strip()

            if not self._is_useful_interface_name(name):
                continue

            ips = []

            for ip in row.get('ip') or []:
                ip = str(ip or '').strip()

                if self._is_useful_ipv4(ip) and ip not in ips:
                    ips.append(ip)

            if not ips:
                continue

            mac = self._normalize_mac(row.get('mac') or '')

            key = (name, tuple(ips), mac)

            if key in seen:
                continue

            seen.add(key)

            result.append({
                'name': name,
                'ip': ', '.join(ips),
                'mac': mac,
            })

        result.sort(key=lambda item: self._interface_sort_key(item.get('name')))
        return result

    def _decode_interface_name(self, value):
        if not value:
            return ''
        return value.decode('utf-8', 'replace')

    def _format_mac_bytes(self, value):
        data = bytes(value or b'')

        if len(data) != 6:
            return ''

        if data == b'\x00\x00\x00\x00\x00\x00':
            return ''

        return ':'.join('{:02x}'.format(part) for part in data)

    def _normalize_mac(self, value):
        text = str(value or '').strip().lower().replace('-', ':')

        if not text:
            return ''

        if ':' in text:
            parts = [part.zfill(2) for part in text.split(':') if part]
        else:
            compact = ''.join(ch for ch in text if ch in '0123456789abcdef')

            if len(compact) != 12:
                return ''

            parts = [
                compact[index:index + 2]
                for index in range(0, 12, 2)
            ]

        if len(parts) != 6:
            return ''

        for part in parts:
            if len(part) != 2:
                return ''

            if any(ch not in '0123456789abcdef' for ch in part):
                return ''

        if parts == ['00', '00', '00', '00', '00', '00']:
            return ''

        return ':'.join(parts)

    def _is_ipv4_family(self, family):
        try:
            return family == socket.AF_INET or int(family) == int(socket.AF_INET)
        except Exception:
            return False

    def _is_psutil_mac_family(self, family, psutil):
        candidates = [
            getattr(psutil, 'AF_LINK', None),
            getattr(socket, 'AF_LINK', None),
            getattr(socket, 'AF_PACKET', None),
        ]

        for candidate in candidates:
            if candidate is None:
                continue

            try:
                if family == candidate or int(family) == int(candidate):
                    return True
            except Exception:
                continue

        return False

    def _is_useful_ipv4(self, ip):
        value = str(ip or '').strip()

        if not value:
            return False

        if value == '0.0.0.0':
            return False

        if value.startswith('127.'):
            return False

        if value.startswith('169.254.'):
            return False

        parts = value.split('.')

        if len(parts) != 4:
            return False

        for part in parts:
            if not part.isdigit():
                return False

            number = int(part)

            if number < 0 or number > 255:
                return False

        return True

    def _is_useful_interface_name(self, name):
        value = str(name or '').strip()

        if not value:
            return False

        lower = value.lower()

        ignored_exact = {
            'lo',
            'lo0',
            'loopback',
        }

        if lower in ignored_exact:
            return False

        ignored_prefixes = (
            'lo',
            'docker',
            'br-',
            'bridge',
            'veth',
            'virbr',
            'vmnet',
            'vboxnet',
            'vethernet',
            'utun',
            'awdl',
            'llw',
            'anpi',
            'gif',
            'stf',
            'ipsec',
        )

        if lower.startswith(ignored_prefixes):
            return False

        ignored_contains = (
            'loopback',
            'virtualbox',
            'vmware',
            'hyper-v',
            'bluetooth',
            'thunderbolt bridge',
            'tunnel',
            'vpn',
        )

        if any(token in lower for token in ignored_contains):
            return False

        return True

    def _interface_sort_key(self, name):
        lower = str(name or '').lower()

        priority_prefixes = (
            'ethernet',
            'en',
            'eth',
            'wi-fi',
            'wifi',
            'wlan',
            'pdp_ip',
        )

        for index, prefix in enumerate(priority_prefixes):
            if lower.startswith(prefix):
                return index, lower

        return len(priority_prefixes), lower