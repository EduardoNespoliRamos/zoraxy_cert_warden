#!/bin/bash
set -e

PLUGIN_ID="${PLUGIN_ID:-com.eduardoramos.zoraxy.certwarden}"
ZORAXY_URL="${ZORAXY_URL:-http://zoraxy:8000}"
COOKIE_JAR="/tmp/cookies.txt"

echo "Waiting for Zoraxy at $ZORAXY_URL..."
for i in $(seq 1 60); do
  if curl -sf "$ZORAXY_URL/api/auth/checkLogin" >/dev/null 2>&1; then
    echo "Zoraxy is up"
    break
  fi
  sleep 1
done

echo "Fetching CSRF token..."
curl -sf -c "$COOKIE_JAR" "$ZORAXY_URL/api/auth/checkLogin" >/dev/null
CSRF_TOKEN=$(grep zoraxy_csrf "$COOKIE_JAR" | awk '{print $7}' | tail -n1)
echo "CSRF token: ${CSRF_TOKEN:0:20}..."

echo "Listing plugins..."
curl -sf -H "X-Zoraxy-Csrf: $CSRF_TOKEN" -b "$COOKIE_JAR" "$ZORAXY_URL/api/plugins/list" || true

echo ""
echo "Enabling plugin $PLUGIN_ID..."
curl -sf -H "X-Zoraxy-Csrf: $CSRF_TOKEN" -b "$COOKIE_JAR" -d "plugin_id=$PLUGIN_ID" "$ZORAXY_URL/api/plugins/enable" || true

echo ""
echo "Waiting for plugin UI..."
for i in $(seq 1 60); do
  if curl -sf -o /tmp/ui.html "$ZORAXY_URL/plugin.ui/$PLUGIN_ID/" 2>/dev/null; then
    echo "Plugin UI is up"
    break
  fi
  sleep 1
done

echo "Fetching plugin UI..."
curl -s -o /tmp/ui.html -w "HTTP %{http_code}\n" "$ZORAXY_URL/plugin.ui/$PLUGIN_ID/" || true
head -c 500 /tmp/ui.html || true

echo ""
echo "Running E2E tests..."
npx playwright test
