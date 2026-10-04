#!/usr/bin/env bash
# scripts/start_lab.sh
set -euo pipefail
mkdir -p data/raw/pcap/classical data/raw/pcap/pqc data/raw/zeek_logs data/raw/telemetry
docker compose up -d --build
docker compose ps