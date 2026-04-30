import socket


class PsutilNetstatProvider:
    """
    TCP/UDP connection provider based on psutil only.

    说明：
    - 不套 shell
    - 不调用 netstat / lsof / ss
    - 不支持 iOS，由 service 层控制
    - macOS 下不使用 psutil.net_connections(kind='inet') 全局读取，
      因为它可能因为某一个受保护 PID AccessDenied 而整体失败。
    - 改为遍历 process.connections/net_connections，单个进程无权限就跳过。
    - 显示每个进程的 PID。
    """

    def collect(self):
        try:
            import psutil
        except Exception as e:
            raise RuntimeError('psutil is required: {}'.format(e))

        rows = []
        seen = set()
        access_denied_count = 0
        error_count = 0

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                connections = self._get_process_connections(proc)
            except psutil.AccessDenied:
                access_denied_count += 1
                continue
            except psutil.NoSuchProcess:
                continue
            except Exception:
                error_count += 1
                continue

            for conn in connections or []:
                row = self._build_row(conn, proc)

                if not row:
                    continue

                key = (
                    row['protocol'],
                    row['local_address'],
                    row['remote_address'],
                    row['status'],
                    row['pid'],  # PID added to the key to avoid duplicates
                )

                if key in seen:
                    continue

                seen.add(key)
                rows.append(row)

        if not rows:
            if access_denied_count:
                raise RuntimeError(
                    'psutil could not read network connections; '
                    '{} processes were denied by the OS'.format(
                        access_denied_count
                    )
                )

            raise RuntimeError(
                'psutil returned no TCP/UDP network connections'
            )

        return rows

    def _get_process_connections(self, proc):
        """
        psutil 6.x 推荐 net_connections。
        老版本使用 connections。

        注意：
        这里不是 shell fallback，只是兼容 psutil API 名称差异。
        """
        if hasattr(proc, 'net_connections'):
            return proc.net_connections(kind='inet')

        return proc.connections(kind='inet')

    def _build_row(self, conn, proc):
        protocol = self._resolve_protocol(getattr(conn, 'type', None))

        if not protocol:
            return None

        local_address, local_port = self._format_address(
            getattr(conn, 'laddr', None)
        )
        remote_address, remote_port = self._format_address(
            getattr(conn, 'raddr', None)
        )
        status = self._format_status(getattr(conn, 'status', None))

        return {
            'protocol': protocol,
            'local_address': local_address,
            'remote_address': remote_address,
            'status': status,
            'pid': proc.pid,  # Include PID here

            # service 层用于端口过滤，最终输出前删除
            '_local_port': local_port,
            '_remote_port': remote_port,
        }

    def _resolve_protocol(self, socket_type):
        try:
            if (
                socket_type == socket.SOCK_STREAM
                or int(socket_type) == int(socket.SOCK_STREAM)
            ):
                return 'tcp'
        except Exception:
            pass

        try:
            if (
                socket_type == socket.SOCK_DGRAM
                or int(socket_type) == int(socket.SOCK_DGRAM)
            ):
                return 'udp'
        except Exception:
            pass

        return ''

    def _format_address(self, addr):
        if not addr:
            return '*:*', None

        ip = ''
        port = None

        if isinstance(addr, tuple):
            if len(addr) >= 1:
                ip = str(addr[0] or '')
            if len(addr) >= 2:
                port = addr[1]
        else:
            ip = str(getattr(addr, 'ip', '') or '')
            port = getattr(addr, 'port', None)

        if not ip:
            ip = '*'

        try:
            port = int(port)
        except Exception:
            port = None

        port_text = '*' if port is None else str(port)

        if ':' in ip and not ip.startswith('['):
            return '[{}]:{}'.format(ip, port_text), port

        return '{}:{}'.format(ip, port_text), port

    def _format_status(self, status):
        value = str(status or '').strip()

        if not value or value.upper() == 'NONE':
            return '-'

        return value