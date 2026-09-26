#!/usr/bin/env bash
set -euo pipefail

# Update only the panel code. Leave Mihomo, Caddy, firewall, and credentials intact.
APP=/opt/apn-admin/app.py
OLD_SHA=20398011020c6786dd46fcedaf7a770c6430e0594a689ffabdf2c814fcd543bb
NEW_SHA=008207b76001d4882c42baeaf5395256a40da2e9b60f11bf8b0e17708c80b6a5
SOURCE=https://raw.githubusercontent.com/8100996-afk/apn/main/app.py

test "$(id -u)" -eq 0 || { echo 'Please run with sudo'; exit 1; }
test -f "$APP" || { echo "Missing $APP"; exit 1; }
current=$(sha256sum "$APP" | cut -d ' ' -f1)
if [ "$current" = "$NEW_SHA" ]; then
  echo 'Panel code is already updated.'
  exit 0
fi
if [ "$current" != "$OLD_SHA" ]; then
  echo "Current app.py has local changes ($current). No files were changed."
  exit 1
fi

tmp=$(mktemp)
backup=$(mktemp)
trap 'rm -f "$tmp" "$backup"' EXIT
curl -fsSL "$SOURCE" -o "$tmp"
echo "$NEW_SHA  $tmp" | sha256sum -c -
python3 -m py_compile "$tmp"
cp -a "$APP" "$backup"
install -m 700 -o root -g root "$tmp" "$APP"
if ! systemctl restart apn-admin || ! systemctl is-active --quiet apn-admin; then
  install -m 700 -o root -g root "$backup" "$APP"
  systemctl restart apn-admin || true
  echo 'Update failed; old panel restored.'
  exit 1
fi
echo 'Updated. Open /switch and use the server IP button.'
