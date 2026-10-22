#!/usr/bin/env python3
"""
extract_ciphertexts.py - pull PsycoSupport ciphertexts out of a packet capture.

Reads a classic .pcap file (as written by `tcpdump -w`), reassembles each TCP
conversation with the server port, parses the JSON payloads, and writes one
CSV row per ciphertext:

    C<n> = Client -> Server  (message_enc, plus username_enc / api_key_enc)
    S<n> = Server -> Client  (ciphertext)

Usage:
    python extract_ciphertexts.py evidence/capture.pcap ciphertexts.csv

Standard library only, so it runs anywhere without installing anything.
"""
import csv
import json
import struct
import sys

SERVER_PORT = 9999


def read_packets(path):
    """Yield raw link-layer frames from a classic pcap file."""
    with open(path, "rb") as f:
        header = f.read(24)
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            sys.exit("Not a classic pcap file (pcapng is not supported).")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            _, _, incl_len, _ = struct.unpack(endian + "IIII", rec)
            yield f.read(incl_len)


def tcp_segments(frames):
    """Yield (src_port, dst_port, seq, payload) for IPv4/TCP frames."""
    for frame in frames:
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":  # Ethernet -> IPv4
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip[2:4])[0]
        if ip[9] != 6:  # TCP
            continue
        tcp = ip[ihl:total_len]
        src_port, dst_port, seq = struct.unpack("!HHI", tcp[:8])
        data_offset = (tcp[12] >> 4) * 4
        payload = tcp[data_offset:]
        if payload:
            yield src_port, dst_port, seq, payload


def reassemble(path):
    """Return conversations in capture order: [(client_bytes, server_bytes), ...]."""
    conversations = {}  # client port -> {"c2s": {seq: data}, "s2c": {seq: data}}
    order = []
    for src, dst, seq, payload in tcp_segments(read_packets(path)):
        if dst == SERVER_PORT:
            client, direction = src, "c2s"
        elif src == SERVER_PORT:
            client, direction = dst, "s2c"
        else:
            continue
        if client not in conversations:
            conversations[client] = {"c2s": {}, "s2c": {}}
            order.append(client)
        conversations[client][direction][seq] = payload  # dedupes retransmits

    def joined(segments):
        return b"".join(segments[s] for s in sorted(segments))

    return [(joined(conversations[c]["c2s"]), joined(conversations[c]["s2c"])) for c in order]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    pcap_path, csv_path = sys.argv[1], sys.argv[2]

    rows = []
    for n, (c2s, s2c) in enumerate(reassemble(pcap_path), start=1):
        request = json.loads(c2s)
        response = json.loads(s2c)
        mood = request.get("mood", "")
        rows.append({
            "id": f"C{n}", "session": n, "direction": "Client -> Server", "mood": mood,
            "field": "message_enc", "ciphertext": request["message_enc"],
            "username_enc": request.get("username_enc", ""),
            "api_key_enc": request.get("api_key_enc", ""),
        })
        rows.append({
            "id": f"S{n}", "session": n, "direction": "Server -> Client", "mood": mood,
            "field": "ciphertext", "ciphertext": response["ciphertext"],
            "username_enc": "", "api_key_enc": "",
        })

    rows.sort(key=lambda r: (r["id"][0], r["session"]))  # C1..C5 then S1..S5
    fields = ["id", "session", "direction", "mood", "field", "length", "ciphertext",
              "username_enc", "api_key_enc"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            r["length"] = len(r["ciphertext"])
            writer.writerow(r)

    for r in rows:
        print(f'{r["id"]:<3} {r["direction"]:<17} mood={r["mood"]:<3} len={r["length"]:<5} {r["ciphertext"][:50]}...')
    print(f"\nWrote {len(rows)} ciphertexts to {csv_path}")


if __name__ == "__main__":
    main()
