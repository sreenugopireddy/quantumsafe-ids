#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=/etc/nginx/certs
CERT_DAYS="${TLS_CLASSICAL_CERT_DAYS:-365}"
PORT="${TLS_CLASSICAL_PORT:-8443}"

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/server.crt" ]]; then
  echo "[tls-classical] generating self-signed certificate..."
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days "$CERT_DAYS" \
    -subj "/CN=tls-classical.lab.local"
fi

export NGINX_PORT="$PORT"
envsubst '${NGINX_PORT}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

echo "[tls-classical] starting nginx on port ${PORT} (TLS 1.3, classical groups only)"
exec nginx -g "daemon off;"