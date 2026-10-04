"""Sends deliberately malformed TLS ClientHello-like byte sequences to a
lab TLS server, for generating malformed_handshake training data.

KNOWN LIMITATION: because these payloads are not valid TLS records (or
are truncated before completion), Zeek's SSL analyzer may fail to log
them in ssl.log at all - only conn.log will show the raw TCP connection.
This means TLSSessionRecord objects (built only from ssl.log rows by
src/parsers/zeek_parser.py) may never be produced for these sessions,
and scripts/label_sessions.py may find zero matching sessions for this
experiment. See KNOWN_LIMITATIONS.md.

Usage:
    python -m scripts.send_malformed_tls --port 8443 --case truncated
"""
from __future__ import annotations

import argparse
import socket
import time


def _truncated_client_hello() -> bytes:
    """A TLS record header claiming a 16-byte ClientHello handshake
    message, but only 4 bytes of body actually follow - truncated
    mid-message."""
    record_header = bytes([0x16, 0x03, 0x01, 0x00, 0x10])
    truncated_body = bytes([0x01, 0x00, 0x00, 0x0C])  # type=ClientHello, length=12, then nothing
    return record_header + truncated_body


def _invalid_extension_length() -> bytes:
    """A ClientHello-shaped message whose declared lengths are
    internally inconsistent with what actually follows."""
    record_header = bytes([0x16, 0x03, 0x01, 0x00, 0x20])
    handshake_header = bytes([0x01, 0x00, 0x00, 0x1C])  # ClientHello, length=28
    client_version = bytes([0x03, 0x03])
    truncated_random = bytes(4)  # should be 32 bytes; deliberately short
    return record_header + handshake_header + client_version + truncated_random


def _garbage_after_client_hello() -> bytes:
    """A plausible-looking TLS record header immediately followed by
    random non-TLS bytes."""
    record_header = bytes([0x16, 0x03, 0x01, 0x00, 0x05])
    garbage = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xFF])
    return record_header + garbage


_PAYLOADS = {
    "truncated": _truncated_client_hello,
    "bad-extension": _invalid_extension_length,
    "garbage": _garbage_after_client_hello,
}


def send_payload(host: str, port: int, case: str, timeout: float = 2.0) -> None:
    payload = _PAYLOADS[case]()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            try:
                sock.recv(4096)
            except (socket.timeout, ConnectionResetError, OSError):
                pass  # expected - server likely closes/resets on malformed input
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        print(f"[send_malformed_tls] connection issue for case={case!r} port={port}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a malformed TLS payload to a lab server.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--case", choices=sorted(_PAYLOADS), required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()

    for _ in range(args.count):
        send_payload(args.host, args.port, args.case)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
