SCRIPT_METADATA = {
    "name": "common/network/fake_ip_check",
    "display_name": "Fake-IP Detection",
    "description": "Check if DNS resolution returns fake-IP addresses by resolving common domains",
    "platforms": ["common"],
    "category": "Network",
    "params": []
}

import socket
import ipaddress


FAKE_NET = ipaddress.ip_network("198.18.0.0/15")


def is_fake_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)

        if addr.version == 4:
            return addr in FAKE_NET

        # 处理类似 ::ffff:0:c612:7 这种把 198.18.0.7 塞进尾部的 IPv6 表示
        tail_v4 = ipaddress.ip_address(addr.packed[-4:])
        if tail_v4 in FAKE_NET and "ffff" in str(addr).lower():
            return True

    except Exception:
        pass

    return False


def resolve(host):
    ips = []

    try:
        infos = socket.getaddrinfo(
            host,
            443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )
    except Exception as e:
        print(host, "DNS error:", repr(e))
        return ips

    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)

    return ips


def main():
    hosts = [
        "baidu.com",
        "apple.com",
        "google.com",
        "cloudflare.com",
    ]

    fake_hits = []

    print("DNS fake-ip check:\n")

    for host in hosts:
        ips = resolve(host)
        print(host, "->", ips)

        for ip in ips:
            if is_fake_ip(ip):
                fake_hits.append((host, ip))

    print("\nResult:")

    if fake_hits:
        print("Shadowrocket fake-ip 大概率开启。")
        print("Fake IP hits:")
        for host, ip in fake_hits:
            print(" ", host, "->", ip)
    else:
        print("没有检测到 fake-ip。")
        print("Shadowrocket 可能关闭,或者没有使用 fake-ip 模式。")


if __name__ == "__main__":
    main()
