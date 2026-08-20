#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-./tmp/test-certs}"
CN="${2:-*.homealone.com.br}"
mkdir -p "$DIR"

openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
    -keyout "$DIR/key0.pem" \
    -out "$DIR/certchain0.pem" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=DNS:$CN"

echo "Generated test certificate in $DIR"
echo "  cert: $DIR/certchain0.pem"
echo "  key:  $DIR/key0.pem"
