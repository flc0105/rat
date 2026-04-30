from client.commands.providers.network.ifconfig_provider import (
    GetifaddrsIfconfigProvider,
    WindowsPsutilIfconfigProvider,
)
from core.platform.platform_identity import detect_platform_alias
from core.utils.command_output import StructuredCommandResult


class NetworkInterfaceService:
    """
    ifconfig service.

    Command facade 调这个 service。
    provider 只负责采集。
    service 负责：
    - 选择 provider
    - 过滤无用网卡
    - 排序
    - 输出 StructuredCommandResult
    """

    def __init__(self, owner=None):
        self.owner = owner

    def build_ifconfig_result(self):
        rows = self.collect_ifconfig_rows()

        if not rows:
            raise RuntimeError('No useful network interfaces found')

        return StructuredCommandResult(
            status=1,
            data=rows,
            shape='table',
        )

    def collect_ifconfig_rows(self):
        platform_alias = detect_platform_alias()

        if platform_alias in ('ios', 'mac', 'linux'):
            provider = GetifaddrsIfconfigProvider(platform_alias)
        elif platform_alias == 'win':
            provider = WindowsPsutilIfconfigProvider()
        else:
            raise RuntimeError(
                'Unsupported platform: {}'.format(platform_alias)
            )

        rows = provider.collect()
        rows = self._filter_and_sort_rows(rows)

        if not rows:
            raise RuntimeError('No useful network interfaces found')

        return rows

    def _filter_and_sort_rows(self, rows):
        result = []
        seen = set()

        for row in rows or []:
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

        result.sort(
            key=lambda item: self._interface_sort_key(item.get('name'))
        )

        return result

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

    def _normalize_mac(self, value):
        text = str(value or '').strip().lower().replace('-', ':')

        if not text:
            return ''

        if ':' in text:
            parts = [part.zfill(2) for part in text.split(':') if part]
        else:
            compact = ''.join(
                ch for ch in text
                if ch in '0123456789abcdef'
            )

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