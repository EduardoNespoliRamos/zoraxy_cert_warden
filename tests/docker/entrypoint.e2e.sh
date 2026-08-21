#!/bin/bash
set -e

PLUGIN_ID="${PLUGIN_ID:-com.eduardoramos.zoraxy.certwarden}"
ZORAXY_URL="${ZORAXY_URL:-http://zoraxy:8000}"
COOKIE_JAR="/tmp/cookies.txt"

echo "Waiting for Zoraxy at $ZORAXY_URL..."
zoraxy_ready=false
for i in $(seq 1 60); do
  if curl -sf "$ZORAXY_URL/api/auth/checkLogin" >/dev/null 2>&1; then
    echo "Zoraxy is up"
    zoraxy_ready=true
    break
  fi
  sleep 1
done
if [[ "$zoraxy_ready" != true ]]; then
  echo "Zoraxy did not become ready" >&2
  exit 1
fi

echo "Fetching CSRF token..."
curl -sf -c "$COOKIE_JAR" "$ZORAXY_URL/api/auth/checkLogin" >/dev/null
CSRF_TOKEN=$(awk '$6 == "zoraxy_csrf" { token = $7 } END { print token }' "$COOKIE_JAR")
if [[ -z "$CSRF_TOKEN" ]]; then
  echo "Zoraxy did not issue a CSRF token" >&2
  exit 1
fi

echo "Listing plugins..."
PLUGIN_LIST=$(curl -sf -H "X-Zoraxy-Csrf: $CSRF_TOKEN" -b "$COOKIE_JAR" "$ZORAXY_URL/api/plugins/list")
printf '%s\n' "$PLUGIN_LIST"
if ! printf '%s' "$PLUGIN_LIST" | grep -q '"id":"'"$PLUGIN_ID"'"'; then
  echo "Plugin $PLUGIN_ID was not discovered" >&2
  exit 1
fi

if ! printf '%s' "$PLUGIN_LIST" | grep -q '"Enabled":true'; then
  echo ""
  echo "Enabling plugin $PLUGIN_ID..."
  curl -sf -H "X-Zoraxy-Csrf: $CSRF_TOKEN" -b "$COOKIE_JAR" -d "plugin_id=$PLUGIN_ID" "$ZORAXY_URL/api/plugins/enable"
fi

echo ""
echo "Waiting for plugin UI..."
plugin_ready=false
for i in $(seq 1 60); do
  if curl -sf -o /tmp/ui.html "$ZORAXY_URL/plugin.ui/$PLUGIN_ID/" 2>/dev/null; then
    echo "Plugin UI is up"
    plugin_ready=true
    break
  fi
  sleep 1
done
if [[ "$plugin_ready" != true ]]; then
  echo "Plugin UI did not become ready" >&2
  exit 1
fi

echo ""
echo "Running E2E tests..."
npx playwright test
