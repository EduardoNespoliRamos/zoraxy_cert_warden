#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-./tmp/test-certs}"
CN="${2:-example.com}"
mkdir -p "$DIR"

rm -f "$DIR/certchain0.pem" "$DIR/key0.pem"

openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
    -keyout "$DIR/key0.pem" \
    -out "$DIR/certchain0.pem" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=DNS:$CN"

echo "Replaced test certificate in $DIR"
