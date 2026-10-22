#!/usr/bin/env bash
# run_demo.sh - send the same kind of patient messages through both hardened channels.
# Run while tcpdump is capturing on lo to show what an eavesdropper now sees.
set -e
cd "$(dirname "$0")"
trap 'kill $SERVER 2>/dev/null || true' EXIT

MESSAGES=("I feel stressed about my exams"
          "My friends have been ignoring me lately and I feel lonely"
          "I have not been sleeping well and I feel tired all the time")

for MODE in tls unix; do
  echo "================ $MODE ================"
  python3 secure_server.py --mode "$MODE" & SERVER=$!
  sleep 2
  for MSG in "${MESSAGES[@]}"; do
    python3 secure_client.py --mode "$MODE" --username Faateh --mood 5 --message "$MSG"
    echo
  done
  kill $SERVER; wait $SERVER 2>/dev/null || true
done
echo "Demo finished: 3 messages over TLS 1.3, 3 over the UNIX socket."
