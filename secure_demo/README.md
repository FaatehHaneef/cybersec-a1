# Secure demo: the two recommended fixes, implemented

A small, separate proof of concept. It does **not** modify the lab's `client`/`server`.
It runs the same kind of exchange (username + mood + concern in, Ollama advice out) over two hardened channels.

| Mode | Fix | What an eavesdropper on loopback sees |
|---|---|---|
| `tls` | TLS 1.3 on 127.0.0.1:9443, self-signed certificate pinned by the client, TLS 1.2 and older refused | Only encrypted TLS records; no words, no mood, no structure |
| `unix` | UNIX domain socket `~/psycare_secure/psycare.sock`, permissions `0600` | Nothing at all. The traffic never touches a network interface, and other users cannot connect |

## Run (Ubuntu / WSL, Ollama running)

```bash
# optional: capture what an attacker would see
sudo tcpdump -i lo -w ~/psycare_secure/secure_capture.pcap 'not port 11434'

bash run_demo.sh          # 3 messages over TLS, 3 over the UNIX socket
```

Analyse the capture with the same attacker's view as the original lab:

```bash
python secure_demo/analyse_secure_capture.py evidence/capture.pcap evidence/secure_capture.pcap output
```

The certificate, private key and socket are created in `~/psycare_secure/` on first run and are never part of the submission.
