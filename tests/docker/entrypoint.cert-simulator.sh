#!/bin/sh
set -e

OUTDIR="${CERT_DIR:-/certs}"
CN="${CERT_CN:-example.com}"
mkdir -p "$OUTDIR"

generate() {
    openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
        -keyout "$OUTDIR/key0.pem" \
        -out "$OUTDIR/certchain0.pem" \
        -subj "/CN=$CN" \
        -addext "subjectAltName=DNS:$CN" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"
    echo "Generated certificate at $(date)"
}

generate

# If RENEW_INTERVAL is set, regenerate periodically.
if [ -n "${RENEW_INTERVAL:-}" ]; then
    while true; do
        sleep "$RENEW_INTERVAL"
        generate
    done
fi
