#!/usr/bin/env python3
"""
relay.py - Groq -> Ollama bridge for the PsycoSupport lab.

The supplied `server` executable was built to call Groq's cloud API with the
model `llama-3.1-8b-instant`, which Groq has retired. We are not allowed to
change the server's functionality, so instead we point it at this relay:

    GROQ_BASE_URL=http://127.0.0.1:8000 ./server

The relay accepts the server's Groq-style requests, swaps the model name for a
local Ollama model, and forwards them to Ollama's OpenAI-compatible API.
Only standard-library modules are used.

Note: request/response *content* is deliberately not logged, so the plaintext
is recovered only through cryptanalysis, as intended.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("RELAY_PORT", "8000"))
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")


def log(msg):
    print(f"[relay {time.strftime('%H:%M:%S')}] {msg}", flush=True)


class RelayHandler(BaseHTTPRequestHandler):
    def _forward(self):
        # Groq's SDK calls /openai/v1/...; Ollama serves the same API at /v1/...
        path = self.path
        if path.startswith("/openai/"):
            path = path[len("/openai"):]

        body = None
        original_model = "-"
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
            try:
                payload = json.loads(body)
                if isinstance(payload, dict) and "model" in payload:
                    original_model = payload["model"]
                    payload["model"] = OLLAMA_MODEL
                    body = json.dumps(payload).encode()
            except ValueError:
                pass  # not JSON: forward unchanged

        req = urllib.request.Request(OLLAMA_URL + path, data=body, method=self.command)
        req.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))

        try:
            resp = urllib.request.urlopen(req, timeout=300)
        except urllib.error.HTTPError as e:
            resp = e
        except urllib.error.URLError as e:
            log(f"{self.command} {self.path} -> Ollama unreachable: {e.reason}")
            self.send_error(502, "Ollama unreachable")
            return

        log(f"{self.command} {self.path}  model: {original_model} -> {OLLAMA_MODEL}  status: {resp.status}")
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
        self.end_headers()
        # Stream the body through so streamed (SSE) completions also work.
        while chunk := resp.read(4096):
            self.wfile.write(chunk)
            self.wfile.flush()

    do_GET = _forward
    do_POST = _forward

    def log_message(self, *args):
        pass  # replaced by our own one-line log


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), RelayHandler)
    log(f"listening on http://{LISTEN_HOST}:{LISTEN_PORT}  ->  {OLLAMA_URL} (model {OLLAMA_MODEL})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
