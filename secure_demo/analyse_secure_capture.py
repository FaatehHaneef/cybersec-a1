#!/usr/bin/env python3
"""
analyse_secure_capture.py - run the same eavesdropping attack on the hardened demo.

Compares the original PsycoSupport capture with a capture of secure_demo traffic:
  * searches the raw packets for words we know were sent (username, concern words)
  * measures Shannon entropy (bits per symbol) of what an eavesdropper sees
  * charts the original's letter frequencies against TLS byte frequencies

Usage:
  python secure_demo/analyse_secure_capture.py evidence/capture.pcap evidence/secure_capture.pcap output
"""
import math
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
from extract_ciphertexts import read_packets, tcp_segments  # noqa: E402

CIPHER, MUTED, GRID = "#2a78d6", "#898781", "#e1e0d9"
KNOWN_WORDS = [b"faateh", b"stressed", b"exams", b"lonely", b"mood"]
TLS_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}


def payload_bytes(path, port):
    return [(src, dst, data) for src, dst, _, data in tcp_segments(read_packets(path)) if port in (src, dst)]


def entropy(counter):
    n = sum(counter.values())
    return -sum(k / n * math.log2(k / n) for k in counter.values())


def tls_records(segments, port):
    """Walk TLS record headers per connection. Returns (record-type counts, encrypted ApplicationData bodies)."""
    streams = {}
    for src, dst, data in segments:
        client = src if dst == port else dst
        direction = "client->server" if dst == port else "server->client"
        streams[(client, direction)] = streams.get((client, direction), b"") + data
    counts, encrypted = Counter(), b""
    for (_, direction), buf in streams.items():
        i = 0
        while i + 5 <= len(buf):
            ctype, length = buf[i], int.from_bytes(buf[i + 3:i + 5], "big")
            counts[(direction, TLS_TYPES.get(ctype, f"type {ctype}"))] += 1
            if ctype == 23:
                encrypted += buf[i + 5:i + 5 + length]
            i += 5 + length
    return counts, encrypted


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    original, secure, out = sys.argv[1:]
    os.makedirs(f"{out}/figures", exist_ok=True)

    orig_segments = payload_bytes(original, 9999)
    orig = b"".join(d for _, _, d in orig_segments)
    sec_segments = payload_bytes(secure, 9443)
    sec = b"".join(d for _, _, d in sec_segments)
    all_secure = b"".join(d for _, _, _, d in tcp_segments(read_packets(secure)))
    record_counts, encrypted = tls_records(sec_segments, 9443)

    # Left chart: one server reply under one key (session 1), as the attacker first analysed it.
    first_reply = next(d for s, _, d in orig_segments if s == 9999)
    orig_letters = Counter(c for c in first_reply.decode(errors="ignore") if c.isalpha() and c.isupper())
    lines = ["# Same attack, hardened channel", "",
             "| | Original PsycoSupport (port 9999) | Secure demo, TLS 1.3 (port 9443) |", "|---|---|---|",
             f"| Payload bytes captured | {len(orig)} | {len(sec)} |",
             f"| Readable structure | JSON keys and `\"mood\": N` in clear | none |"]
    for w in KNOWN_WORDS:
        lines.append(f"| Known word `{w.decode()}` found in packets | "
                     f"{'yes' if w in orig.lower() else 'no'} | {'yes' if w in sec.lower() else 'no'} |")
    lines += [f"| Symbols an attacker sees | {len(orig_letters)} letters A-Z (session 1 reply) | "
              f"{len(set(encrypted))} of 256 byte values (encrypted record bodies) |",
              f"| Shannon entropy | {entropy(orig_letters):.2f} bits/letter (max 4.70; English ~4.1) | "
              f"{entropy(Counter(encrypted)):.2f} bits/byte (max 8.00) |",
              "| Frequency analysis result | key recovered, all text decrypted | nothing to map; no letters |", ""]

    lines += ["TLS records seen by the eavesdropper (secure capture):", ""]
    for (direction, rtype), k in sorted(record_counts.items()):
        lines.append(f"- {direction}: {k} x {rtype}")
    # Every other loopback flow in the secure capture, checked for leaked plaintext.
    flows = {}
    for src, dst, _, data in tcp_segments(read_packets(secure)):
        server_port = min(src, dst)  # the listening port is the low, fixed one
        flows[server_port] = flows.get(server_port, b"") + data
    lines += ["", "All loopback flows in the secure capture (Ollama's main port 11434 was filtered out):", "",
              "| Port | Payload bytes | `\"username\"` (client request) | `faateh` | `stressed` | What it is |",
              "|---:|---:|:---:|:---:|:---:|---|"]
    for port, data in sorted(flows.items()):
        low = data.lower()
        what = "secure demo, TLS 1.3" if port == 9443 else "Ollama internal model runner (server -> LLM hop)"
        found = ["yes" if word in low else "no" for word in (b'"username"', b"faateh", b"stressed")]
        lines.append(f"| {port} | {len(data)} | {' | '.join(found)} | {what} |")
    lines += ["",
              f"- The UNIX-socket client->server exchange never appears: no flow contains the `\"username\"` request "
              f"({len(all_secure)} payload bytes checked).",
              "- Ollama passes each prompt to its model runner over plain HTTP on loopback, so the concern is still "
              "visible on that hop. Securing the client<->server channel alone is not enough: every hop that carries "
              "patient data (including server -> LLM) needs the same protection, e.g. Ollama on a UNIX socket or "
              "an in-process model.", ""]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.4), gridspec_kw={"width_ratios": [1, 1.6]})
    n = sum(orig_letters.values())
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ax1.bar(list(letters), [100 * orig_letters[c] / n for c in letters], color=CIPHER, width=0.7)
    ax1.set_title("Original S1: affine ciphertext letters (peaky = breakable)", loc="left", fontweight="bold", fontsize=9)
    ax1.set_ylabel("% of symbols")
    sb = Counter(encrypted)
    ax2.bar(range(256), [100 * sb[i] / len(encrypted) for i in range(256)], color=CIPHER, width=1.0)
    ax2.axhline(100 / 256, color=MUTED, linewidth=1, linestyle="--")
    ax2.text(255, 100 / 256, " uniform", color=MUTED, va="bottom", ha="right", fontsize=8)
    ax2.set_title("Secure demo: TLS 1.3 encrypted bytes 0-255 (flat = nothing to analyse)", loc="left",
                  fontweight="bold", fontsize=9)
    ax2.set_ylim(0, max(ax1.get_ylim()[1], 1))  # same scale as the left chart, for a fair visual
    ax2.set_xlim(-1, 256)
    for ax in (ax1, ax2):
        ax.grid(axis="y", color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.tick_params(colors=MUTED, labelsize=8)
    fig.tight_layout()
    fig.savefig(f"{out}/figures/secure_vs_original.png", dpi=150)
    plt.close(fig)

    with open(f"{out}/secure_comparison.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
