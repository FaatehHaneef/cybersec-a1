#!/usr/bin/env python3
"""
server.py - PsycoSupport server backed by a local Ollama model.

The lab's original server sent each concern to Groq's cloud model
(llama-3.1-8b-instant), which has been retired. This version keeps the
server's functionality and wire protocol unchanged, so the original
`client` works with it as-is, and replaces the Groq call with a local
Ollama model (llama3.2). Nothing leaves the machine.

Protocol (recovered by cryptanalysis of captured traffic, see report):
  * TCP, default 0.0.0.0:9999, one JSON request and one JSON reply per connection.
  * Request:  {"username_enc", "mood", "message_enc", "api_key_enc"}
      Each character is written as two hex digits; each digit (0-15) is
      affine-encrypted as a letter: E(d) = (a*d + b) mod 26.
  * Reply:    {"ciphertext": ...}
      The advice is upper-cased, reduced to letters and spaces, and
      affine-encrypted letter by letter with the same key.
  * Key schedule: a = 2*mood + 1, b = 2*mood (mod 26).
The API-key field is ignored (everything runs locally).

Usage:  python3 server.py [--host 0.0.0.0] [--port 9999] [--model llama3.2]
Requires Ollama running locally (ollama serve) with the model pulled.
"""
import argparse
import json
import socket
import urllib.error
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
SYSTEM_PROMPT = ("You are a warm, supportive psychologist. Address the patient by their name at the start of your "
                 "reply. Acknowledge their feelings and give practical, gentle suggestions in one or two short "
                 "paragraphs. Do not use lists or headings. You are not a substitute for professional care.")


# ---- classical affine layer (unchanged behaviour) ----------------------------

def key_for_mood(mood):
    return (2 * mood + 1) % 26, (2 * mood) % 26


def decrypt_field(text, a, b):
    """Letters -> hex digits -> characters (client -> server direction)."""
    a_inv = pow(a, -1, 26)
    letters = [c for c in text.upper() if "A" <= c <= "Z"]
    digits = [(a_inv * (ord(c) - 65 - b)) % 26 for c in letters]
    return "".join(chr(16 * digits[i] + digits[i + 1]) for i in range(0, len(digits) - 1, 2))


def normalise(reply):
    """Upper-case, turn line breaks into spaces, keep only letters and spaces."""
    reply = reply.upper().replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return "".join(c for c in reply if "A" <= c <= "Z" or c == " ").strip()


def encrypt_reply(text, a, b):
    """Server -> client direction: affine on letters, spaces kept."""
    return "".join(chr((a * (ord(c) - 65) + b) % 26 + 65) if c != " " else " " for c in text)


# ---- local model --------------------------------------------------------------

def ask_ollama(model, username, mood, message):
    payload = {"model": model, "stream": False, "messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Patient name: {username}\nMood (1-10): {mood}\nConcern: {message}"}]}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)["message"]["content"]


# ---- connection handling ------------------------------------------------------

def read_request(conn):
    """Read until the buffer holds one complete JSON object (the client sends no delimiter)."""
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        try:
            return json.loads(buf)
        except ValueError:
            continue
    return json.loads(buf)


def handle(conn, addr, model):
    request = read_request(conn)
    mood = int(request["mood"])
    a, b = key_for_mood(mood)
    try:
        username = decrypt_field(request["username_enc"], a, b)
        message = decrypt_field(request["message_enc"], a, b)
    except ValueError:  # a has no inverse mod 26 (mood 6 -> a = 13)
        print(f"[{addr}] mood={mood} gives a={a}, which is not invertible mod 26; request unreadable")
        username, message = "Patient", "(unreadable message)"
    print(f"[{addr}] user={username} mood={mood} msg_len={len(message)}")

    try:
        advice = ask_ollama(model, username, mood, message)
    except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
        print(f"[{addr}] Ollama request failed: {e}")
        advice = f"{username}, I'm having trouble responding right now. Please try again in a moment."
    if not normalise(advice).startswith(normalise(username)):
        advice = f"{username}, {advice}"

    reply = {"ciphertext": encrypt_reply(normalise(advice), a, b)}
    conn.sendall(json.dumps(reply).encode())


def main():
    p = argparse.ArgumentParser(description="PsycoSupport server (local Ollama backend)")
    p.add_argument("--host", default="0.0.0.0", help="bind address (use 127.0.0.1 to stay loopback-only)")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--model", default="llama3.2")
    args = p.parse_args()

    with socket.create_server((args.host, args.port), reuse_port=False) as srv:
        print(f"[SERVER] Ollama-backed ({args.model}) | Listening on {args.host}:{args.port}", flush=True)
        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    handle(conn, addr, args.model)
                except (ValueError, KeyError, OSError) as e:
                    print(f"[{addr}] bad request: {e}", flush=True)


if __name__ == "__main__":
    main()
