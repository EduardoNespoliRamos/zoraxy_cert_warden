#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Running unit tests..."
go test ./...

echo ""
echo "To run integration tests via Docker Compose, use: make integration-test"
