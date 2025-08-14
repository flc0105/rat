# from scapy.all import *
# from scapy.layers.http import HTTPRequest
#
#
# def process_packet(packet):
#     if packet.haslayer(HTTPRequest):
#         url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
#         print(f"HTTP Request to: {url}")
#
#         if packet.haslayer(Raw):
#             print(f"Raw data: {packet[Raw].load.decode()}")
#
#
# import psutil
#
# def get_active_network_interfaces():
#     active_interfaces = []
#     for interface, stats in psutil.net_if_stats().items():
#         if stats.isup:  # 检查网卡是否活跃
#             active_interfaces.append(interface)
#     return active_interfaces
#
#
#
# active_interfaces = get_active_network_interfaces()
# print("当前活跃的网络接口:", active_interfaces)
#
#
# # 通常 Wi-Fi 或以太网是 en0
# primary_interface = "en0" if "en0" in active_interfaces else active_interfaces[0]
# print("推荐使用的网卡:", primary_interface)
#
# # # 开始抓包（需要管理员权限）
# sniff(iface=primary_interface, prn=process_packet, store=False)



# from scapy.all import *
#
# def packet_callback(packet):
#     print(packet.summary())  # 打印所有包的摘要
#
# sniff(iface="en0", prn=packet_callback)  # 只抓10个包


from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS
import sys


def process_packet(packet):
    # 1. 检查 HTTP 明文请求
    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]
        host = http.Host.decode() if http.Host else ""
        path = http.Path.decode() if http.Path else ""
        print(f"[HTTP] {host}{path}")

    # 2. 检查 HTTPS 域名 (SNI)
    elif packet.haslayer(TLS):
        tls = packet[TLS]
        if hasattr(tls, 'handshake') and tls.handshake.type == 1:  # Client Hello
            for ext in tls.handshake.extensions:
                if ext.type == 0x00:  # SNI 扩展
                    print(f"[HTTPS] Domain: {ext.servername.decode()}")


if __name__ == "__main__":
    iface = "en0"  # 手动指定网卡
    print(f"Monitoring interface: {iface}")
    try:
        sniff(iface=iface,
              prn=process_packet,
              filter="tcp port 80 or tcp port 443",  # HTTP + HTTPS
              store=False)
    except PermissionError:
        print("需要管理员权限！请使用:")
        print(f"sudo python3 {sys.argv[0]}")
    except KeyboardInterrupt:
        print("\n捕获结束")