#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p ./tmp/plugin ./tmp/test-certs ./tmp/target

if [ ! -f ./tmp/test-certs/certchain0.pem ]; then
    ./scripts/generate-test-cert.sh ./tmp/test-certs
fi

cat > ./tmp/plugin/config.json <<EOF
{
  "certificates": [
    {
      "name": "homealone-wildcard",
      "enabled": true,
      "source": {
        "certificate": "$ROOT/tmp/test-certs/certchain0.pem",
        "private_key": "$ROOT/tmp/test-certs/key0.pem"
      },
      "destination": {
        "target_directory": "$ROOT/tmp/target",
        "target_name": "homealone-wildcard"
      },
      "sync": {
        "auto_sync": true,
        "filesystem_watch": true,
        "poll_interval_seconds": 5
      },
      "fallback": true
    }
  ]
}
EOF

go build -o ./tmp/plugin/com.eduardoramos.zoraxy.certwarden ./cmd/cert-sync

CONFIGURE='{"port": 19090, "runtime_const": {"zoraxy_version": "3.3.3", "zoraxy_uuid": "dev", "development_build": true}}'
./tmp/plugin/com.eduardoramos.zoraxy.certwarden -configure="$CONFIGURE"
