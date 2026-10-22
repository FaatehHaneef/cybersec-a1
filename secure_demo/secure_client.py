#!/usr/bin/env python3
"""
secure_client.py - client for secure_server.py.

TLS mode verifies the server against its self-signed certificate (pinned via
cafile) and checks the hostname, so a man-in-the-middle with a different
certificate is rejected. UNIX mode connects to the owner-only socket file.

Usage:
  python3 secure_client.py --mode tls  --username Faateh --mood 5 --message "I feel stressed about my exams"
  python3 secure_client.py --mode unix --username Faateh --mood 5 --message "I feel stressed about my exams"
"""
import argparse
import json
import socket
import ssl

from secure_server import CERT, SOCK, TLS_PORT


def main():
    p = argparse.ArgumentParser(description="Client for the hardened PsycoSupport-style server")
    p.add_argument("--mode", choices=["tls", "unix"], required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--mood", type=int, required=True)
    p.add_argument("--message", required=True)
    args = p.parse_args()

    if args.mode == "tls":
        ctx = ssl.create_default_context(cafile=CERT)  # trust only our certificate
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        raw = socket.create_connection(("127.0.0.1", TLS_PORT))
        conn = ctx.wrap_socket(raw, server_hostname="localhost")
        print(f"[client] connected with {conn.version()}, cipher {conn.cipher()[0]}")
    else:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(SOCK)
        print(f"[client] connected to UNIX socket {SOCK}")

    with conn, conn.makefile("rwb") as f:
        request = {"username": args.username, "mood": args.mood, "message": args.message}
        f.write(json.dumps(request).encode() + b"\n")
        f.flush()
        print("[client] reply:", json.loads(f.readline())["reply"])


if __name__ == "__main__":
    main()
