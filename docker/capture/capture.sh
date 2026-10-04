#!/usr/bin/env bash
set -euo pipefail

TARGET_NAME="${CAPTURE_TARGET_NAME:?CAPTURE_TARGET_NAME is required}"
TARGET_PORT="${CAPTURE_TARGET_PORT:?CAPTURE_TARGET_PORT is required}"
OUT_DIR="${CAPTURE_OUT_DIR:-/captures}"
ROTATE_SECONDS="${CAPTURE_ROTATE_SECONDS:-300}"
SNAPLEN="${CAPTURE_SNAPLEN:-262144}"

mkdir -p "$OUT_DIR"
echo "[capture-${TARGET_NAME}] capturing tcp port ${TARGET_PORT} -> ${OUT_DIR}, rotating every ${ROTATE_SECONDS}s"

exec tcpdump -i any \
  -U \
  -s "$SNAPLEN" \
  -G "$ROTATE_SECONDS" \
  -w "${OUT_DIR}/${TARGET_NAME}_%Y%m%d_%H%M%S.pcap" \
  "tcp port ${TARGET_PORT}"