import socket
import time


class iOSNetworkService:
    """
    iOS / Pythonista 网络探测能力。
    """

    def __init__(self, owner):
        self.owner = owner

    def tcp_ping(self, host, port=80, count=4, timeout=2.0):
        self.owner._send_interim_result(1, "TCP ping {}:{} count={} timeout={}s".format(
            host, port, count, timeout
        ))

        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except Exception as e:
            self.owner._send_final_result(0, f"DNS failed: {repr(e)}")
            return

        addr = infos[0][4]
        self.owner._send_interim_result(1, f"resolved: {addr}")

        times = []

        for i in range(count):
            s = socket.socket(infos[0][0], socket.SOCK_STREAM)
            s.settimeout(timeout)

            start = time.time()

            try:
                s.connect(addr)
                elapsed = (time.time() - start) * 1000.0
                times.append(elapsed)
                self.owner._send_interim_result(1, "reply {}: {:.1f} ms".format(i + 1, elapsed))
            except Exception as e:
                self.owner._send_interim_result(0, "timeout/error {}: {}".format(i + 1, repr(e)))
            finally:
                s.close()

            time.sleep(1)

        if times:
            self.owner._send_interim_result(1, "")
            self.owner._send_final_result(1, "min/avg/max = {:.1f}/{:.1f}/{:.1f} ms".format(
                min(times),
                sum(times) / len(times),
                max(times)
            ))
        else:
            self.owner._send_final_result(1, "\n")

    def acmd_tcp_ping(self, args_dict):
        try:
            host = str(args_dict.get('host') or '').strip()
            port = int(args_dict.get('port') or '')
            count = int(args_dict.get('count') or '')
            return self.tcp_ping(host=host, port=port, count=count)
        except Exception as e:
            return 0, str(e)