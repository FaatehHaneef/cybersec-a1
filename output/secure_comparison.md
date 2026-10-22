# Same attack, hardened channel

| | Original PsycoSupport (port 9999) | Secure demo, TLS 1.3 (port 9443) |
|---|---|---|
| Payload bytes captured | 5464 | 6286 |
| Readable structure | JSON keys and `"mood": N` in clear | none |
| Known word `faateh` found in packets | no | no |
| Known word `stressed` found in packets | no | no |
| Known word `exams` found in packets | no | no |
| Known word `lonely` found in packets | no | no |
| Known word `mood` found in packets | yes | no |
| Symbols an attacker sees | 23 letters A-Z (session 1 reply) | 256 of 256 byte values (encrypted record bodies) |
| Shannon entropy | 4.18 bits/letter (max 4.70; English ~4.1) | 7.96 bits/byte (max 8.00) |
| Frequency analysis result | key recovered, all text decrypted | nothing to map; no letters |

TLS records seen by the eavesdropper (secure capture):

- client->server: 6 x ApplicationData
- client->server: 3 x ChangeCipherSpec
- client->server: 3 x Handshake
- server->client: 21 x ApplicationData
- server->client: 3 x ChangeCipherSpec
- server->client: 3 x Handshake

All loopback flows in the secure capture (Ollama's main port 11434 was filtered out):

| Port | Payload bytes | `"username"` (client request) | `faateh` | `stressed` | What it is |
|---:|---:|:---:|:---:|:---:|---|
| 9443 | 6286 | no | no | no | secure demo, TLS 1.3 |
| 39237 | 81893 | no | yes | yes | Ollama internal model runner (server -> LLM hop) |

- The UNIX-socket client->server exchange never appears: no flow contains the `"username"` request (88179 payload bytes checked).
- Ollama passes each prompt to its model runner over plain HTTP on loopback, so the concern is still visible on that hop. Securing the client<->server channel alone is not enough: every hop that carries patient data (including server -> LLM) needs the same protection, e.g. Ollama on a UNIX socket or an in-process model.
