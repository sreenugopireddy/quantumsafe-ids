#!/bin/sh
set -eu

CERT_DIR=/etc/nginx/certs
PORT="${PQC_TLS_PORT:-8444}"
GROUPS="${PQC_GROUPS:-X25519MLKEM768}"
ALLOW_FALLBACK="${PQC_ALLOW_CLASSICAL_FALLBACK:-true}"

for bin in openssl envsubst nginx; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[tls-pqc] FATAL: required tool '$bin' not found in PQC_BASE_IMAGE."
    echo "[tls-pqc] Build a base image that includes openssl, gettext (envsubst), and nginx."
    exit 1
  fi
done

mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -subj "/CN=tls-pqc.lab.local"
fi

# Detect whether this OpenSSL build actually knows the requested KEM/group.
# Do NOT assume a specific PQC package (oqs-provider, liboqs, etc.) is present.
PQC_STATUS="unavailable"
if openssl list -kem-algorithms 2>/dev/null | grep -qi "$GROUPS"; then
  PQC_STATUS="confirmed"
fi

case "$PQC_STATUS" in
  confirmed)
    echo "[tls-pqc] PQC group '${GROUPS}' confirmed in this OpenSSL build. Enabling."
    SSL_GROUPS_DIRECTIVE="ssl_ecdh_curve ${GROUPS};"
    ;;
  *)
    if [ "$ALLOW_FALLBACK" != "true" ]; then
      echo "[tls-pqc] FATAL: PQC group '${GROUPS}' not available and"
      echo "[tls-pqc] PQC_ALLOW_CLASSICAL_FALLBACK=false. Set PQC_BASE_IMAGE to a"
      echo "[tls-pqc] PQC-capable build (e.g. an oqs-provider OpenSSL/nginx image)."
      exit 1
    fi
    echo "[tls-pqc] WARNING: PQC group '${GROUPS}' not confirmed in this OpenSSL build."
    echo "[tls-pqc] Falling back to a classical group. Traffic from this server MUST NOT"
    echo "[tls-pqc] be auto-labeled benign_hybrid_pqc (label 1) — verify with"
    echo "[tls-pqc]   openssl s_client -connect localhost:${PORT} -groups ${GROUPS}"
    echo "[tls-pqc] (see scripts/verify_lab_capture.sh) before trusting labels."
    SSL_GROUPS_DIRECTIVE="ssl_ecdh_curve X25519;"
    ;;
esac

export NGINX_PORT="$PORT"
export SSL_GROUPS_DIRECTIVE
envsubst '${NGINX_PORT} ${SSL_GROUPS_DIRECTIVE}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

exec nginx -g "daemon off;"