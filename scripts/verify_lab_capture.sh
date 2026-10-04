#!/usr/bin/env bash
set -euo pipefail
source .env 2>/dev/null || true
 
echo "== Container health =="
docker compose ps

echo -e "\n== TLS handshake: classical (port ${TLS_CLASSICAL_PORT:-8443}) =="
echo | openssl s_client -connect localhost:${TLS_CLASSICAL_PORT:-8443} -tls1_3 2>/dev/null \
  | grep -E "Protocol|Cipher|Verify return code"

echo -e "\n== TLS handshake: pqc (port ${PQC_TLS_PORT:-8444}) =="
echo | openssl s_client -connect localhost:${PQC_TLS_PORT:-8444} -tls1_3 -groups "${PQC_GROUPS:-X25519MLKEM768}" 2>/dev/null \
  | grep -E "Protocol|Cipher|Verify return code|Negotiated"

echo -e "\n== PCAP capture =="
ls -la data/raw/pcap/classical/ data/raw/pcap/pqc/ 2>/dev/null || echo "no pcap files yet - wait for first rotation"

echo -e "\n== Zeek logs =="
find data/raw/zeek_logs -maxdepth 2 -type f 2>/dev/null | head -20 || echo "no zeek logs yet"

echo -e "\n== Telemetry =="
tail -n 5 data/raw/telemetry/endpoint_telemetry.csv 2>/dev/null || echo "no telemetry file yet"