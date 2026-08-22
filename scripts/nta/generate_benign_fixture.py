#!/usr/bin/env python3
"""Generate a local-only benign HTTP PCAP for NTA false-positive regression."""

from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path


CLIENT_IP = "10.10.0.1"
SERVER_IP = "10.10.0.2"
SERVER_PORT = 8080
BASE_TIMESTAMP = 1_787_304_608


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ethernet_ipv4_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
    identification: int = 1,
) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_without_checksum = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        65_535,
        0,
        0,
    )
    pseudo_header = src + dst + struct.pack(
        "!BBH", 0, 6, len(tcp_without_checksum) + len(payload)
    )
    tcp_checksum = internet_checksum(pseudo_header + tcp_without_checksum + payload)
    tcp = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        65_535,
        tcp_checksum,
        0,
    )
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        identification,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        identification,
        0x4000,
        64,
        6,
        internet_checksum(ip_without_checksum),
        src,
        dst,
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp + payload


def http_request(path: str, body: bytes) -> bytes:
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: internal.example\r\n"
        "User-Agent: ShieldChain-Benign-Fixture/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return headers.encode("ascii") + body


def http_response(body: bytes) -> bytes:
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return headers.encode("ascii") + body


def build_fixture(output: Path) -> int:
    packets: list[bytes] = []
    identification = 1

    def add_flow(src_port: int, request: bytes, response: bytes) -> None:
        nonlocal identification
        client_sequence = 1_000
        server_sequence = 5_000
        packets.extend(
            [
                ethernet_ipv4_tcp_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    src_port,
                    SERVER_PORT,
                    client_sequence,
                    0,
                    0x02,
                    identification=identification,
                ),
                ethernet_ipv4_tcp_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    src_port,
                    server_sequence,
                    client_sequence + 1,
                    0x12,
                    identification=identification + 1,
                ),
                ethernet_ipv4_tcp_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    src_port,
                    SERVER_PORT,
                    client_sequence + 1,
                    server_sequence + 1,
                    0x10,
                    identification=identification + 2,
                ),
            ]
        )
        identification += 3
        client_sequence += 1
        server_sequence += 1

        for offset in range(0, len(request), 1_200):
            chunk = request[offset : offset + 1_200]
            packets.append(
                ethernet_ipv4_tcp_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    src_port,
                    SERVER_PORT,
                    client_sequence,
                    server_sequence,
                    0x18,
                    chunk,
                    identification,
                )
            )
            identification += 1
            client_sequence += len(chunk)

        packets.append(
            ethernet_ipv4_tcp_frame(
                SERVER_IP,
                CLIENT_IP,
                SERVER_PORT,
                src_port,
                server_sequence,
                client_sequence,
                0x10,
                identification=identification,
            )
        )
        identification += 1

        for offset in range(0, len(response), 1_200):
            chunk = response[offset : offset + 1_200]
            packets.append(
                ethernet_ipv4_tcp_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    src_port,
                    server_sequence,
                    client_sequence,
                    0x18,
                    chunk,
                    identification,
                )
            )
            identification += 1
            server_sequence += len(chunk)

        packets.extend(
            [
                ethernet_ipv4_tcp_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    src_port,
                    SERVER_PORT,
                    client_sequence,
                    server_sequence,
                    0x11,
                    identification=identification,
                ),
                ethernet_ipv4_tcp_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    src_port,
                    server_sequence,
                    client_sequence + 1,
                    0x11,
                    identification=identification + 1,
                ),
            ]
        )
        identification += 2

    add_flow(
        41_001,
        http_request("/report.php", b"range=30d"),
        http_response(b"R" * 40_000),
    )
    add_flow(
        41_002,
        http_request("/api/search", b"fish=" + b"A" * 120),
        http_response(b"ok"),
    )
    add_flow(
        41_003,
        http_request("/search.php", b"fish=" + b"A" * 120),
        http_response(b"ok"),
    )
    add_flow(
        41_004,
        http_request(
            "/login.php",
            b"username=alice&password=synthetic-demo-only",
        ),
        http_response(b"welcome"),
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
        for index, packet in enumerate(packets):
            handle.write(
                struct.pack(
                    "<IIII",
                    BASE_TIMESTAMP + index // 100,
                    (index % 100) * 10_000,
                    len(packet),
                    len(packet),
                )
            )
            handle.write(packet)
    return len(packets)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic benign HTTP PCAP without sending traffic"
    )
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = build_fixture(args.output.resolve())
    print(f"{args.output.resolve()} packets={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
