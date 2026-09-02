import ctypes
import os
import socket
import sys
import threading
import time

from core.protocol.message_types import (
    MSG_TYPE_MONITOR_CLOSED,
    MSG_TYPE_MONITOR_ERROR,
    MSG_TYPE_MONITOR_OPENED,
    MSG_TYPE_MONITOR_SNAPSHOT,
)


class DeviceMonitorManager:
    """
    Client 端轻量设备监控会话。

    监控数据独立于 command foreground task，只在 Server 明确打开会话后采集。
    不同 channel 使用各自采样周期，避免低频指标跟随 CPU / Network 高频刷新。
    """

    SUPPORTED_CHANNELS = {'system', 'storage', 'network', 'battery'}
    DEFAULT_INTERVALS = {
        'system': 0.5,
        'network': 0.5,
        'storage': 5.0,
        'battery': 5.0,
    }
    MIN_INTERVAL_SECONDS = 0.25
    MAX_INTERVAL_SECONDS = 60.0

    def __init__(self, connection):
        self.connection = connection
        self._lock = threading.RLock()
        self._sessions = {}

    def open_session(self, monitor_session_id: str, channels=None, intervals=None):
        monitor_session_id = str(monitor_session_id or '').strip()
        if not monitor_session_id:
            return

        normalized_channels = self._normalize_channels(channels)
        normalized_intervals = self._normalize_intervals(intervals, normalized_channels)

        self.close_session(monitor_session_id, notify=False)

        item = {
            'monitor_session_id': monitor_session_id,
            'channels': normalized_channels,
            'intervals': normalized_intervals,
            'stop_event': threading.Event(),
            'notify_close': True,
            'network_baseline': None,
            'seq': 0,
        }
        worker = threading.Thread(
            target=self._run_session,
            args=(item,),
            daemon=True,
            name=f'device-monitor-{monitor_session_id[:8]}',
        )
        item['worker'] = worker

        with self._lock:
            self._sessions[monitor_session_id] = item

        worker.start()

    def update_session(self, monitor_session_id: str, channels=None, intervals=None):
        monitor_session_id = str(monitor_session_id or '').strip()
        with self._lock:
            item = self._sessions.get(monitor_session_id)
            if not item:
                return

            next_channels = self._normalize_channels(
                item.get('channels') if channels is None else channels
            )
            next_intervals = self._normalize_intervals(
                item.get('intervals') if intervals is None else intervals,
                next_channels,
            )
            item['channels'] = next_channels
            item['intervals'] = next_intervals

    def close_session(self, monitor_session_id: str, notify: bool = True):
        monitor_session_id = str(monitor_session_id or '').strip()
        with self._lock:
            item = self._sessions.get(monitor_session_id)
            if not item:
                return
            if not notify:
                item['notify_close'] = False
            item['stop_event'].set()

    def close_all_sessions(self, notify: bool = False):
        with self._lock:
            items = list(self._sessions.values())
            for item in items:
                if not notify:
                    item['notify_close'] = False
                item['stop_event'].set()

    def _run_session(self, item: dict):
        monitor_session_id = item['monitor_session_id']
        try:
            import psutil

            # cpu_percent / network rate 都需要前一帧基线，启动时先预热一次。
            psutil.cpu_percent(interval=None)
            item['network_baseline'] = self._read_network_baseline(psutil)

            self._send({
                'type': MSG_TYPE_MONITOR_OPENED,
                'monitor_session_id': monitor_session_id,
                'channels': list(item.get('channels') or []),
                'intervals': dict(item.get('intervals') or {}),
            })

            now = time.monotonic()
            next_due = {}
            for channel in item.get('channels') or []:
                if channel in ('storage', 'battery'):
                    next_due[channel] = now
                else:
                    next_due[channel] = now + float(item['intervals'].get(channel, 0.5))

            while not item['stop_event'].is_set():
                with self._lock:
                    channels = list(item.get('channels') or [])
                    intervals = dict(item.get('intervals') or {})

                now = time.monotonic()
                for channel in channels:
                    if channel not in next_due:
                        next_due[channel] = now
                    if now < next_due[channel]:
                        continue

                    data = self._collect_channel(channel, psutil, item)
                    item['seq'] += 1
                    self._send({
                        'type': MSG_TYPE_MONITOR_SNAPSHOT,
                        'monitor_session_id': monitor_session_id,
                        'seq': item['seq'],
                        'channel': channel,
                        'data': data,
                        'collected_at': time.time(),
                    })
                    next_due[channel] = now + float(intervals.get(channel, 1.0))

                for channel in list(next_due.keys()):
                    if channel not in channels:
                        next_due.pop(channel, None)

                item['stop_event'].wait(0.05)

        except Exception as e:
            self._send_safely({
                'type': MSG_TYPE_MONITOR_ERROR,
                'monitor_session_id': monitor_session_id,
                'message': str(e) or 'Device monitor failed',
            })
        finally:
            with self._lock:
                current = self._sessions.get(monitor_session_id)
                notify_close = bool(current.get('notify_close')) if current else bool(item.get('notify_close'))
                self._sessions.pop(monitor_session_id, None)

            if notify_close:
                self._send_safely({
                    'type': MSG_TYPE_MONITOR_CLOSED,
                    'monitor_session_id': monitor_session_id,
                })

    def _collect_channel(self, channel: str, psutil, item: dict) -> dict:
        if channel == 'system':
            return self._collect_system(psutil)
        if channel == 'storage':
            return self._collect_storage(psutil)
        if channel == 'network':
            return self._collect_network(psutil, item)
        if channel == 'battery':
            return self._collect_battery(psutil)
        return {}

    def _collect_system(self, psutil) -> dict:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        uptime_seconds = max(0.0, time.time() - float(psutil.boot_time()))

        cpu_percent = round(float(psutil.cpu_percent(interval=None)), 1)

        # macOS 下 psutil 的非阻塞 CPU 采样偶尔会出现单帧 0.0。
        # 仅过滤孤立的 0% 毛刺；如果连续两帧都是 0%，则按真实 0% 显示。
        if sys.platform == 'darwin':
            now = time.monotonic()
            state = getattr(self, '_mac_cpu_deglitch_state', None)

            if not isinstance(state, dict):
                state = {
                    'last_valid': None,
                    'last_valid_at': 0.0,
                    'zero_pending': False,
                }
                self._mac_cpu_deglitch_state = state

            if cpu_percent == 0.0:
                last_valid = state.get('last_valid')
                last_valid_at = float(state.get('last_valid_at') or 0.0)
                last_valid_age = now - last_valid_at

                if (
                        not state.get('zero_pending')
                        and last_valid is not None
                        and float(last_valid) > 0.0
                        and last_valid_age <= 1.5
                ):
                    cpu_percent = float(last_valid)
                    state['zero_pending'] = True
                else:
                    state['zero_pending'] = True
            else:
                state['last_valid'] = cpu_percent
                state['last_valid_at'] = now
                state['zero_pending'] = False

        return {
            'cpu_percent': cpu_percent,
            'cpu_count': int(psutil.cpu_count(logical=True) or 0),
            'memory': {
                'total': int(memory.total or 0),
                'used': int(memory.used or 0),
                'available': int(memory.available or 0),
                'percent': round(float(memory.percent or 0), 1),
            },
            'swap': {
                'total': int(swap.total or 0),
                'used': int(swap.used or 0),
                'free': int(swap.free or 0),
                'percent': round(float(swap.percent or 0), 1),
            },
            'uptime_seconds': int(uptime_seconds),
            'process_count': len(psutil.pids()),
        }

    # def _collect_system(self, psutil) -> dict:
    #     memory = psutil.virtual_memory()
    #     swap = psutil.swap_memory()
    #     uptime_seconds = max(0.0, time.time() - float(psutil.boot_time()))
    #
    #     return {
    #         'cpu_percent': round(float(psutil.cpu_percent(interval=None)), 1),
    #         'cpu_count': int(psutil.cpu_count(logical=True) or 0),
    #         'memory': {
    #             'total': int(memory.total or 0),
    #             'used': int(memory.used or 0),
    #             'available': int(memory.available or 0),
    #             'percent': round(float(memory.percent or 0), 1),
    #         },
    #         'swap': {
    #             'total': int(swap.total or 0),
    #             'used': int(swap.used or 0),
    #             'free': int(swap.free or 0),
    #             'percent': round(float(swap.percent or 0), 1),
    #         },
    #         'uptime_seconds': int(uptime_seconds),
    #         'process_count': len(psutil.pids()),
    #     }

    def _collect_storage(self, psutil) -> dict:
        volumes = []
        seen_mounts = set()

        for partition in psutil.disk_partitions(all=False):
            mountpoint = str(partition.mountpoint or '').strip()
            if not mountpoint or mountpoint in seen_mounts:
                continue
            if not self._should_include_volume(partition):
                continue

            seen_mounts.add(mountpoint)
            try:
                usage = psutil.disk_usage(mountpoint)
            except Exception:
                continue

            meta = self._volume_metadata(partition)
            normalized_usage = self._normalize_volume_usage(partition, usage)
            volumes.append({
                'name': meta['name'],
                'mountpoint': mountpoint,
                'device': str(partition.device or ''),
                'fstype': str(partition.fstype or ''),
                'kind': meta['kind'],
                'system': bool(meta['system']),
                'total': normalized_usage['total'],
                'used': normalized_usage['used'],
                'free': normalized_usage['free'],
                'percent': normalized_usage['percent'],
            })

        volumes.sort(key=lambda item: (not item.get('system'), str(item.get('name') or '').casefold()))
        return {'volumes': volumes}

    def _normalize_volume_usage(self, partition, usage) -> dict:
        total = int(getattr(usage, 'total', 0) or 0)
        used = int(getattr(usage, 'used', 0) or 0)
        free = int(getattr(usage, 'free', 0) or 0)
        percent = round(float(getattr(usage, 'percent', 0) or 0), 1)

        mountpoint = str(getattr(partition, 'mountpoint', '') or '').strip()
        fstype = str(getattr(partition, 'fstype', '') or '').strip().lower()

        # macOS 的 APFS System Volume(/) 与 Data Volume 共用 container。
        # psutil 对 / 的 used/percent 可能只反映 sealed System Volume，
        # 但 total/free 又是共享 container 语义，导致三者无法相加。
        # Dashboard 的系统盘卡片按 container 容量展示，保证 used + free = total。
        if sys.platform == 'darwin' and mountpoint == '/' and fstype == 'apfs' and total > 0:
            free = max(0, min(free, total))
            used = max(0, total - free)
            percent = round((used / total) * 100.0, 1)

        return {
            'total': total,
            'used': used,
            'free': free,
            'percent': percent,
        }

    def _collect_network(self, psutil, item: dict) -> dict:
        now = time.monotonic()
        counters = psutil.net_io_counters()
        current = (
            int(getattr(counters, 'bytes_recv', 0) or 0),
            int(getattr(counters, 'bytes_sent', 0) or 0),
            now,
        )
        previous = item.get('network_baseline')
        item['network_baseline'] = current

        rx_per_sec = 0.0
        tx_per_sec = 0.0
        if previous:
            elapsed = max(current[2] - float(previous[2]), 0.001)
            rx_per_sec = max(0.0, (current[0] - int(previous[0])) / elapsed)
            tx_per_sec = max(0.0, (current[1] - int(previous[1])) / elapsed)

        interface_name, ipv4 = self._find_active_interface(psutil)
        return {
            'rx_bytes_per_sec': int(rx_per_sec),
            'tx_bytes_per_sec': int(tx_per_sec),
            'bytes_received': current[0],
            'bytes_sent': current[1],
            'interface': interface_name,
            'ipv4': ipv4,
        }

    def _collect_battery(self, psutil) -> dict:
        try:
            battery = psutil.sensors_battery()
        except Exception:
            battery = None

        if battery is None:
            return {'available': False}

        return {
            'available': True,
            'percent': round(float(battery.percent or 0), 1),
            'plugged': bool(battery.power_plugged),
            'seconds_left': self._normalize_battery_seconds_left(
                getattr(battery, 'secsleft', None),
                psutil,
            ),
        }

    def _read_network_baseline(self, psutil):
        try:
            counters = psutil.net_io_counters()
            return (
                int(getattr(counters, 'bytes_recv', 0) or 0),
                int(getattr(counters, 'bytes_sent', 0) or 0),
                time.monotonic(),
            )
        except Exception:
            return None

    def _find_active_interface(self, psutil):
        try:
            all_stats = psutil.net_if_stats()
            all_addrs = psutil.net_if_addrs()
        except Exception:
            return '', ''

        fallback = ('', '')
        for name, addresses in all_addrs.items():
            stats = all_stats.get(name)
            if stats is not None and not stats.isup:
                continue

            ipv4 = ''
            for addr in addresses:
                if getattr(addr, 'family', None) == socket.AF_INET:
                    candidate = str(getattr(addr, 'address', '') or '').strip()
                    if candidate:
                        ipv4 = candidate
                        break

            if not ipv4:
                continue
            if ipv4.startswith('127.'):
                if not fallback[0]:
                    fallback = (name, ipv4)
                continue
            return name, ipv4

        return fallback

    def _should_include_volume(self, partition) -> bool:
        mountpoint = str(partition.mountpoint or '').strip()
        fstype = str(partition.fstype or '').strip().lower()

        if sys.platform == 'darwin':
            return mountpoint == '/' or mountpoint.startswith('/Volumes/')

        if sys.platform.startswith('win'):
            drive_type = self._windows_drive_type(mountpoint)
            return drive_type not in (0, 1, 5)

        pseudo_fs = {
            'proc', 'sysfs', 'devtmpfs', 'devfs', 'tmpfs', 'squashfs', 'overlay',
            'cgroup', 'cgroup2', 'pstore', 'securityfs', 'debugfs', 'tracefs',
        }
        return fstype not in pseudo_fs

    def _volume_metadata(self, partition) -> dict:
        mountpoint = str(partition.mountpoint or '').strip()
        fstype = str(partition.fstype or '').strip().lower()

        if sys.platform.startswith('win'):
            drive_type = self._windows_drive_type(mountpoint)
            kind_map = {
                2: 'removable',
                3: 'local',
                4: 'network',
                6: 'ramdisk',
            }
            system_drive = str(os.environ.get('SystemDrive') or '').rstrip('\\/').casefold()
            current_drive = mountpoint.rstrip('\\/').casefold()
            label = self._windows_volume_label(mountpoint)
            return {
                'name': label or mountpoint.rstrip('\\/') or mountpoint,
                'kind': kind_map.get(drive_type, 'local'),
                'system': bool(system_drive and current_drive == system_drive),
            }

        if sys.platform == 'darwin':
            network_fs = {'smbfs', 'nfs', 'afpfs', 'webdav'}
            if mountpoint == '/':
                return {'name': 'System Volume', 'kind': 'system', 'system': True}
            name = os.path.basename(mountpoint.rstrip('/')) or mountpoint
            return {
                'name': name,
                'kind': 'network' if fstype in network_fs else 'external',
                'system': False,
            }

        network_fs = {'nfs', 'nfs4', 'cifs', 'smbfs', 'sshfs', 'fuse.sshfs'}
        name = '/' if mountpoint == '/' else (os.path.basename(mountpoint.rstrip('/')) or mountpoint)
        return {
            'name': 'System Volume' if mountpoint == '/' else name,
            'kind': 'network' if fstype in network_fs else 'local',
            'system': mountpoint == '/',
        }

    def _windows_drive_type(self, mountpoint: str) -> int:
        if not sys.platform.startswith('win'):
            return 0
        try:
            root = mountpoint
            if len(root) == 2 and root[1] == ':':
                root += '\\'
            return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))
        except Exception:
            return 3

    def _windows_volume_label(self, mountpoint: str) -> str:
        if not sys.platform.startswith('win'):
            return ''
        try:
            root = mountpoint
            if len(root) == 2 and root[1] == ':':
                root += '\\'
            volume_name = ctypes.create_unicode_buffer(261)
            fs_name = ctypes.create_unicode_buffer(261)
            serial = ctypes.c_ulong()
            max_component = ctypes.c_ulong()
            flags = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(root),
                volume_name,
                len(volume_name),
                ctypes.byref(serial),
                ctypes.byref(max_component),
                ctypes.byref(flags),
                fs_name,
                len(fs_name),
            )
            return volume_name.value.strip() if ok else ''
        except Exception:
            return ''

    def _normalize_battery_seconds_left(self, value, psutil):
        try:
            seconds = int(value)
        except Exception:
            return None

        unknown_values = {
            int(getattr(psutil, 'POWER_TIME_UNKNOWN', -2)),
            int(getattr(psutil, 'POWER_TIME_UNLIMITED', -1)),
        }
        if seconds < 0 or seconds in unknown_values:
            return None
        return seconds

    def _normalize_channels(self, channels) -> list[str]:
        raw = channels if isinstance(channels, (list, tuple, set)) else []
        normalized = []
        for channel in raw:
            name = str(channel or '').strip().lower()
            if name in self.SUPPORTED_CHANNELS and name not in normalized:
                normalized.append(name)
        return normalized or ['system', 'storage', 'network', 'battery']

    def _normalize_intervals(self, intervals, channels) -> dict:
        raw = intervals if isinstance(intervals, dict) else {}
        result = {}
        for channel in channels:
            default = self.DEFAULT_INTERVALS[channel]
            try:
                value = float(raw.get(channel, default))
            except Exception:
                value = default
            result[channel] = max(self.MIN_INTERVAL_SECONDS, min(self.MAX_INTERVAL_SECONDS, value))
        return result

    def _send(self, payload: dict):
        self.connection.send(payload)

    def _send_safely(self, payload: dict):
        try:
            self._send(payload)
        except Exception:
            pass
