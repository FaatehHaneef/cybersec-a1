#!/usr/bin/env python3
"""
secure_server.py - a hardened PsycoSupport-style server (proof of concept).

Same job as the lab server (username + mood + concern in, supportive advice
from the local Ollama model out), but the client<->server channel is protected
with one of the two fixes recommended in the report:

  --mode tls   TCP on 127.0.0.1:9443 wrapped in TLS 1.3 (self-signed cert).
               An eavesdropper on loopback only sees random-looking bytes.
  --mode unix  A UNIX domain socket file with permissions 0600. Traffic never
               touches the network stack, so tcpdump/Wireshark see nothing,
               and only the owning user can connect.

The certificate, key and socket live in ~/psycare_secure (created on first run)
and are never committed or submitted. Standard library only (+ openssl CLI).

Usage:  python3 secure_server.py --mode tls|unix
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import urllib.request

STATE_DIR = os.path.expanduser(os.environ.get("PSYCARE_SECURE_DIR", "~/psycare_secure"))
CERT = os.path.join(STATE_DIR, "server.crt")
KEY = os.path.join(STATE_DIR, "server.key")
SOCK = os.path.join(STATE_DIR, "psycare.sock")
TLS_PORT = 9443
OLLAMA = "http://127.0.0.1:11434/api/chat"
MODEL = "llama3.2"


def ensure_certificate():
    """Create a self-signed certificate for localhost the first time we run."""
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "30", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", KEY, "-out", CERT], check=True, capture_output=True)
    os.chmod(KEY, 0o600)
    print(f"[secure] created self-signed certificate {CERT}")


def advice(username, mood, message):
    prompt = {"model": MODEL, "stream": False, "messages": [
        {"role": "system", "content": "You are a supportive psychologist. Reply in 2-3 sentences."},
        {"role": "user", "content": f"Patient {username}, mood {mood}/10: {message}"}]}
    try:
        req = urllib.request.Request(OLLAMA, data=json.dumps(prompt).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.load(resp)["message"]["content"]
    except OSError:
        return f"{username}, thank you for sharing. Take a slow breath; you are not alone in this."


def serve_one(conn):
    with conn, conn.makefile("rwb") as f:
        request = json.loads(f.readline())
        print(f"[secure] request from user={request['username']} mood={request['mood']}")
        reply = advice(request["username"], request["mood"], request["message"])
        f.write(json.dumps({"reply": reply}).encode() + b"\n")
        f.flush()


def main():
    p = argparse.ArgumentParser(description="Hardened PsycoSupport-style server")
    p.add_argument("--mode", choices=["tls", "unix"], required=True)
    p.add_argument("--once", action="store_true", help="exit after one request")
    args = p.parse_args()
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)

    if args.mode == "tls":
        ensure_certificate()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # refuse anything older
        ctx.load_cert_chain(CERT, KEY)
        listener = socket.create_server(("127.0.0.1", TLS_PORT))
        print(f"[secure] TLS 1.3 server on 127.0.0.1:{TLS_PORT}")
    else:
        if os.path.exists(SOCK):
            os.remove(SOCK)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(SOCK)
        os.chmod(SOCK, 0o600)                          # owner-only access
        listener.listen()
        print(f"[secure] UNIX socket server on {SOCK} (mode 0600)")

    with listener:
        while True:
            conn, _ = listener.accept()
            if args.mode == "tls":
                try:
                    conn = ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError as e:
                    print(f"[secure] rejected handshake: {e.reason}")
                    conn.close()
                    continue
                print(f"[secure] handshake ok: {conn.version()} {conn.cipher()[0]}")
            serve_one(conn)
            if args.once:
                break


if __name__ == "__main__":
    main()
