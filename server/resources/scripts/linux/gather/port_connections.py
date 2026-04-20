#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import socket
import subprocess

TARGET_PORT = 9999


def run_ss_listen():
    p = subprocess.run(
        ["ss", "-lntp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "ss -lntp failed")
    return p.stdout


def run_ss_conn():
    p = subprocess.run(
        ["ss", "-ntp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "ss -ntp failed")
    return p.stdout


def split_addr(addr):
    addr = addr.strip()

    if addr.startswith("[") and "]:" in addr:
        i = addr.rfind("]:")
        return addr[1:i], int(addr[i + 2:])

    i = addr.rfind(":")
    if i == -1:
        return addr, None

    host = addr[:i]
    port = addr[i + 1:]

    try:
        return host, int(port)
    except ValueError:
        return host, None


def parse_proc(text):
    procs = []
    for name, pid, fd in re.findall(r'"([^"]+)",pid=(\d+),fd=(\d+)', text):
        procs.append(
            {
                "process_name": name,
                "pid": int(pid),
                "fd": int(fd),
            }
        )
    return procs


def parse_listen_socket(raw):
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("State "):
            continue

        parts = line.split(None, 5)
        if len(parts) < 5:
            continue

        state = parts[0]
        recv_q = parts[1]
        send_q = parts[2]
        local_addr = parts[3]
        proc_text = parts[5] if len(parts) >= 6 else ""

        local_host, local_port = split_addr(local_addr)
        if local_port != TARGET_PORT:
            continue

        return {
            "state": state,
            "recv_q": int(recv_q) if recv_q.isdigit() else recv_q,
            "send_q": int(send_q) if send_q.isdigit() else send_q,
            "local_ip": local_host,
            "local_port": local_port,
            "processes": parse_proc(proc_text),
            "raw_process": proc_text,
        }

    return None


def parse_connections(raw):
    connections = []

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("State "):
            continue

        parts = line.split(None, 6)
        if len(parts) < 6:
            continue

        state = parts[0]
        recv_q = parts[1]
        send_q = parts[2]
        local_addr = parts[3]
        peer_addr = parts[4]
        proc_text = parts[5] if len(parts) == 6 else parts[6]

        local_host, local_port = split_addr(local_addr)
        peer_host, peer_port = split_addr(peer_addr)

        if local_port != TARGET_PORT:
            continue

        item = {
            "state": state,
            "recv_q": int(recv_q) if recv_q.isdigit() else recv_q,
            "send_q": int(send_q) if send_q.isdigit() else send_q,
            "local_ip": local_host,
            "local_port": local_port,
            "peer_ip": peer_host,
            "peer_port": peer_port,
            "peer_reverse_dns": None,
            "processes": parse_proc(proc_text),
            "raw_process": proc_text,
        }

        try:
            item["peer_reverse_dns"] = socket.gethostbyaddr(peer_host)[0]
        except Exception:
            pass

        connections.append(item)

    return connections


listen_raw = run_ss_listen()
conn_raw = run_ss_conn()

listen_socket = parse_listen_socket(listen_raw)
active_connections = parse_connections(conn_raw)

result = {
    "target_port": TARGET_PORT,
    "listen_socket": listen_socket,
    "active_connection_count": len(active_connections),
    "active_connections": active_connections,
}

print(json.dumps(result, ensure_ascii=False, indent=2))