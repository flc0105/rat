import ipaddress
import os
import select
import socket
import struct
import time

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
FAKE_NET = ipaddress.ip_network("198.18.0.0/15")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    s = 0

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xffff) + (s >> 16)

    return (~s) & 0xffff


def is_fake_ip(ip):
    try:
        return ipaddress.ip_address(ip) in FAKE_NET
    except Exception:
        return False


def make_packet(ident, seq):
    payload = struct.pack("!d", time.time()) + b"Q" * 48

    header = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        0,
        ident,
        seq
    )

    csum = checksum(header + payload)

    header = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        csum,
        ident,
        seq
    )

    return header + payload


def parse_icmp_packet(packet):
    """
    Darwin/iOS 收到的 IPv4 ICMP 包通常前面带 IPv4 header。
    这里自动判断并跳过。
    """
    if len(packet) < 8:
        return None

    offset = 0

    # IPv4 header: version = 4
    if len(packet) >= 28 and (packet[0] >> 4) == 4:
        ip_header_len = (packet[0] & 0x0f) * 4
        protocol = packet[9]

        if protocol == socket.IPPROTO_ICMP:
            offset = ip_header_len

    if len(packet) < offset + 8:
        return None

    icmp_header = packet[offset:offset + 8]

    icmp_type, code, recv_checksum, ident, seq = struct.unpack(
        "!BBHHH",
        icmp_header
    )

    payload = packet[offset + 8:]

    return {
        "type": icmp_type,
        "code": code,
        "checksum": recv_checksum,
        "id": ident,
        "seq": seq,
        "payload": payload,
    }


def do_one_ping(host, timeout=2.0, seq=1):
    try:
        dest_ip = socket.gethostbyname(host)
    except Exception as e:
        return {
            "ok": False,
            "error": "DNS error: {}".format(repr(e)),
        }

    if is_fake_ip(dest_ip):
        return {
            "ok": False,
            "ip": dest_ip,
            "error": "resolved to fake-ip; Shadowrocket fake-ip may be active",
        }

    ident = os.getpid() & 0xffff
    packet = make_packet(ident, seq)

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_ICMP
        )
    except Exception as e:
        return {
            "ok": False,
            "ip": dest_ip,
            "error": "cannot create ICMP socket: {}".format(repr(e)),
        }

    sock.settimeout(timeout)

    try:
        send_time = time.time()
        sock.sendto(packet, (dest_ip, 1))

        time_left = timeout

        while time_left > 0:
            start_select = time.time()

            ready = select.select([sock], [], [], time_left)

            select_time = time.time() - start_select

            if not ready[0]:
                return {
                    "ok": False,
                    "ip": dest_ip,
                    "error": "timeout",
                }

            recv_time = time.time()
            data, addr = sock.recvfrom(4096)

            parsed = parse_icmp_packet(data)

            if not parsed:
                time_left -= select_time
                continue

            if (
                    parsed["type"] == ICMP_ECHO_REPLY
                    and parsed["code"] == 0
                    and parsed["id"] == ident
                    and parsed["seq"] == seq
            ):
                rtt_ms = (recv_time - send_time) * 1000.0

                return {
                    "ok": True,
                    "ip": dest_ip,
                    "from": addr[0],
                    "rtt_ms": rtt_ms,
                    "seq": seq,
                }

            time_left -= select_time

        return {
            "ok": False,
            "ip": dest_ip,
            "error": "timeout",
        }

    finally:
        sock.close()
