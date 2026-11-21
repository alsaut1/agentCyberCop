#!/bin/sh
# HT CYBERCOP agent (Watcher) installer.
#
#   curl -fsSL https://@HOST@/install.sh | sudo sh -s -- CODE
#
# CODE is the one-time code from the control centre. The script downloads the agent, checks its SHA-256, creates
# the system user cybercop-agent, installs a systemd service and registers the server. The agent only reads and
# reports; it opens no ports. Remove it with:  sudo sh install.sh --uninstall
set -eu

SERVER="https://@HOST@"
VERSION="@VERSION@"
SHA256_X86_64="@SHA256_X86_64@"
BIN=/usr/local/bin/cybercop-agent
STATE=/var/lib/cybercop-agent
UNIT=/etc/systemd/system/cybercop-agent.service
USER_NAME=cybercop-agent

say() { printf 'cybercop-agent: %s\n' "$*"; }
die() { say "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: curl -fsSL $SERVER/install.sh | sudo sh -s -- CODE"

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now cybercop-agent cybercop-agent-update.path 2>/dev/null || true
  rm -f "$UNIT" "$BIN" /etc/systemd/system/cybercop-agent-update.service /etc/systemd/system/cybercop-agent-update.path
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$STATE"
  id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null || true
  say "removed. Revoke the agent in the control centre as well."
  exit 0
fi

CODE="${1:-}"
[ -n "$CODE" ] || die "usage: curl -fsSL $SERVER/install.sh | sudo sh -s -- CODE"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64; SUM="$SHA256_X86_64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="$SERVER/agent-api/v1/download/$VERSION/$ARCH"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --proto '=https' -o "$TMP/cybercop-agent" "$URL" || die "download failed: $URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$TMP/cybercop-agent" "$URL" || die "download failed: $URL"
else
  die "curl or wget is required"
fi
echo "$SUM  $TMP/cybercop-agent" | sha256sum -c - >/dev/null 2>&1 || die "checksum mismatch, not installing"

if ! id "$USER_NAME" >/dev/null 2>&1; then
  NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --home-dir "$STATE" --no-create-home --shell "$NOLOGIN" "$USER_NAME"
fi
install -m 0755 -o root -g root "$TMP/cybercop-agent" "$BIN"
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE"

cat > "$UNIT" <<UNIT
[Unit]
Description=HT CYBERCOP agent (Watcher): inventory and signs of a break-in, read-only
Wants=network-online.target
After=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
ExecStart=$BIN run
Restart=on-failure
RestartSec=60
# Read-only access to files of other users (package databases, crontabs, authorized_keys). Nothing else.
AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=256M
CPUQuota=25%
Nice=10

[Install]
WantedBy=multi-user.target
UNIT

# Root updater: started when the agent has downloaded and checked a signed version; checks it again on its own copy.
cat > /etc/systemd/system/cybercop-agent-update.service <<UNIT
[Unit]
Description=HT CYBERCOP agent updater (installs a signed version only)

[Service]
Type=oneshot
ExecStart=$BIN apply-update
UNIT
cat > /etc/systemd/system/cybercop-agent-update.path <<UNIT
[Unit]
Description=HT CYBERCOP agent: a downloaded update is waiting

[Path]
PathExists=$STATE/update/ready
Unit=cybercop-agent-update.service

[Install]
WantedBy=multi-user.target
UNIT

if [ ! -f "$STATE/agent.json" ]; then
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$USER_NAME" -- "$BIN" enroll --server "$SERVER" "$CODE" || die "registration failed"
  else
    su -s /bin/sh "$USER_NAME" -c "'$BIN' enroll --server '$SERVER' '$CODE'" || die "registration failed"
  fi
fi
systemctl daemon-reload
systemctl enable --now cybercop-agent cybercop-agent-update.path >/dev/null
say "installed $VERSION; the first inventory appears in the control centre within a few minutes"
