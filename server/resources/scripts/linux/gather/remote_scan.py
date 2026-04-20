#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import ssl
import json
import html
import socket
import argparse
from urllib.request import Request, urlopen


DEFAULT_HOST = "127.0.0.1"

# 这里只是默认测试端口集合，不是全端口扫描。
# 你本地测试先用这些，之后按目标环境自己增减。
DEFAULT_PORTS = [
    22, 80, 81, 88, 443,
    5000, 5003,
    8000, 8001,
    8080, 8081, 8082, 8083, 8084, 8085,
    8443, 9000, 9999
]


def tcp_connect(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def banner_probe(host, port, timeout=2.0):
    result = {
        "protocol_hint": None,
        "banner": None
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
            except Exception:
                data = b""

            if not data:
                return result

            text = data.decode("utf-8", errors="ignore").strip()
            result["banner"] = text or None

            if text.startswith("SSH-"):
                result["protocol_hint"] = "ssh"
            elif text.startswith("220 "):
                result["protocol_hint"] = "ftp"

            return result
    except Exception:
        return result


def extract_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return None
    title = html.unescape(m.group(1))
    title = re.sub(r"\s+", " ", title).strip()
    return title or None


def http_probe(url, insecure=False, timeout=2.5):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
    ctx = ssl._create_unverified_context() if insecure else None

    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(65536)
            body = raw.decode("utf-8", errors="ignore")
            return {
                "ok": True,
                "status": getattr(r, "status", None),
                "server_header": r.headers.get("Server"),
                "content_type": r.headers.get("Content-Type"),
                "title": extract_title(body),
                "final_url": r.geturl(),
            }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e)
        }


def scan_one(host, port):
    row = {
        "host": host,
        "port": port,
        "tcp_open": False,
        "protocol_hint": None,
        "banner": None,
    }

    if not tcp_connect(host, port):
        return row

    row["tcp_open"] = True

    b = banner_probe(host, port)
    row["protocol_hint"] = b["protocol_hint"]
    row["banner"] = b["banner"]

    return row


def detect_web(host, port):
    http_url = f"http://{host}:{port}/"
    https_url = f"https://{host}:{port}/"

    r = http_probe(http_url, insecure=False)
    if r["ok"]:
        r["http_type"] = "http"
        r["url"] = http_url
        return r

    r = http_probe(https_url, insecure=True)
    if r["ok"]:
        r["http_type"] = "https"
        r["url"] = https_url
        return r

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST, help="target host, default 127.0.0.1")
    parser.add_argument("--ports", default=",".join(str(x) for x in DEFAULT_PORTS), help="comma separated ports")
    args = parser.parse_args()

    host = args.host.strip()
    ports = []
    for x in args.ports.split(","):
        x = x.strip()
        if not x:
            continue
        ports.append(int(x))

    open_ports = []
    web_services = []

    for port in ports:
        info = scan_one(host, port)
        if not info["tcp_open"]:
            continue

        open_ports.append(info)

        web = detect_web(host, port)
        if web:
            web_services.append({
                "host": host,
                "port": port,
                "http_type": web["http_type"],
                "status": web["status"],
                "server_header": web["server_header"],
                "content_type": web["content_type"],
                "title": web["title"],
                "final_url": web["final_url"],
            })

    result = {
        "target": host,
        "open_ports": open_ports,
        "web_services": web_services,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))


main()