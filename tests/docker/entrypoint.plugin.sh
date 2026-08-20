#!/bin/sh
set -e

PLUGIN_DIR="/opt/zoraxy/plugin/com.eduardoramos.zoraxy.certwarden"
mkdir -p "$PLUGIN_DIR"
cp /plugin/com.eduardoramos.zoraxy.certwarden "$PLUGIN_DIR/"
chmod +x "$PLUGIN_DIR/com.eduardoramos.zoraxy.certwarden"

echo "Plugin installed at $PLUGIN_DIR"
