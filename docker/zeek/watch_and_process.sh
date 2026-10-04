#!/usr/bin/env bash
set -uo pipefail   # NOTE: no -e here - a single failed pcap must not kill the loop

PCAP_DIR="${ZEEK_PCAP_DIR:-/captures}"
LOG_ROOT="${ZEEK_LOG_DIR:-/zeek_logs}"
MARKER_DIR="${LOG_ROOT}/.processed"
FAILED_DIR="${LOG_ROOT}/.failed"

mkdir -p "$LOG_ROOT" "$MARKER_DIR" "$FAILED_DIR"

process_pcap() {
  local pcap_path="$1"
  local base marker size1 size2 size3 out_dir
  base="$(basename "$pcap_path" .pcap)"
  marker="${MARKER_DIR}/${base}.done"
  [[ -f "$marker" ]] && return 0

  # skip files tcpdump is still actively writing (triple-checked)
  size1=$(stat -c%s "$pcap_path")
  sleep 5
  size2=$(stat -c%s "$pcap_path")
  [[ "$size1" != "$size2" ]] && return 0
  sleep 5
  size3=$(stat -c%s "$pcap_path")
  [[ "$size2" != "$size3" ]] && return 0
  [[ "$size1" -eq 0 ]] && { echo "[zeek] skipping empty file: $pcap_path"; touch "$marker"; return 0; }

  out_dir="${LOG_ROOT}/${base}"
  mkdir -p "$out_dir"
  echo "[zeek] processing ${pcap_path} -> ${out_dir}"

  if (cd "$out_dir" && zeek -C -r "$pcap_path" local); then
    touch "$marker"
  else
    echo "[zeek] WARNING: failed to process ${pcap_path} (likely truncated/corrupt) - moving aside, not retrying"
    rm -rf "$out_dir"
    mv "$pcap_path" "${FAILED_DIR}/" 2>/dev/null || true
    touch "$marker"
  fi
}

echo "[zeek] watching ${PCAP_DIR} for completed pcap rotations"
while true; do
  for subdir in classical pqc; do
    # Only process files EXCEPT the most recent one per subdir - tcpdump
    # is still actively writing to the newest file, so it can never be
    # considered final no matter how stable its size appears.
    mapfile -t files < <(ls -1t "${PCAP_DIR}/${subdir}"/*.pcap 2>/dev/null)
    for ((idx = 1; idx < ${#files[@]}; idx++)); do
      process_pcap "${files[idx]}"
    done
  done
  sleep 5
done