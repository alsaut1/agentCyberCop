#!/bin/sh
# HT CYBERCOP agent (Watcher) installer.
#
#   curl -fsSL https://raw.githubusercontent.com/alsaut1/agentCyberCop/vX.Y.Z/dist/install.sh | sudo sh -s -- CODE
#
# CODE is the one-time code from the control centre. Take this script from the public repository, not from the
# control centre: the release keys below are what makes the download trustworthy. The script asks the control
# centre which version is current, downloads it, and installs it only if its Ed25519 signature verifies with one
# of the release keys (main or spare) and the version is not older than this script. The signature is made offline
# by the maintainer; the control centre cannot produce one. Then it creates the system user cybercop-agent,
# installs a systemd service and registers the server. The agent only reads and reports; it opens no ports.
#
#   --server URL                    another control centre (https only)
#   --install-python3-cryptography  RHEL 8 family: agree in advance to install the distribution package needed
#                                   to check the signature (asked interactively otherwise)
#   --uninstall                     remove the agent
set -eu

SERVER="https://agent.cybercop.gtva.net"
# Oldest version this installer accepts: the version of the tag it was published with. An older signed version may
# have known holes, so a control centre cannot push one to a new server.
MIN_VERSION="0.1.2"
# Release keys, "name:base64-public-key" separated by spaces: main and spare (the maintainer keeps the secret halves
# offline). Without keys nothing can be installed.
RELEASE_KEYS="main:v1uiLKxvYbHr42+wVOqPtFOWNk/IxiElaVT1uGvRg+k= spare:ilfuIb2sW3tq5YJQDx9fLwRicTvrA+8j8VO498GVIuQ="
PREFIX="cybercop-agent-release-v1"
BIN=/usr/local/bin/cybercop-agent
STATE=/var/lib/cybercop-agent
UNIT=/etc/systemd/system/cybercop-agent.service
USER_NAME=cybercop-agent

say() { printf 'cybercop-agent: %s\n' "$*"; }
die() { say "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"

CODE=""
AGREE_PKG=no
UNINSTALL=no
while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) UNINSTALL=yes ;;
    --install-python3-cryptography) AGREE_PKG=yes ;;
    --server) [ $# -ge 2 ] || die "--server needs a URL"; SERVER="$2"; shift ;;
    --server=*) SERVER="${1#--server=}" ;;
    -*) die "unknown option: $1" ;;
    *) CODE="$1" ;;
  esac
  shift
done

if [ "$UNINSTALL" = yes ]; then
  systemctl disable --now cybercop-agent cybercop-agent-update.path 2>/dev/null || true
  rm -f "$UNIT" "$BIN" /etc/systemd/system/cybercop-agent-update.service /etc/systemd/system/cybercop-agent-update.path
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$STATE"
  id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null || true
  say "removed. Revoke the agent in the control centre as well."
  exit 0
fi

[ -n "$CODE" ] || die "usage: ... | sudo sh -s -- CODE   (the one-time code from the control centre)"
case "$SERVER" in https://*) ;; *) die "the control centre address must start with https://" ;; esac
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
[ -n "$RELEASE_KEYS" ] || die "this installer has no release keys yet, so nothing can be verified; not installing"

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {  # URL FILE
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1"
  else
    die "curl or wget is required"
  fi
}

# --- which version: only the number, checksum and signature come from the control centre -------------------------
fetch "$SERVER/agent-api/v1/release?arch=$ARCH" "$TMP/release.json" || die "cannot ask $SERVER for the current version"
field() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$TMP/release.json" | head -1; }
VERSION=$(field version); SUM=$(field sha256); SIG=$(field signature)
echo "$VERSION" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$' || die "the control centre sent a bad version"
echo "$SIG" | grep -Eq '^[A-Za-z0-9+/]{86}==$' || die "the current version $VERSION is not signed yet; not installing"
echo "$SUM" | grep -Eq '^[0-9a-f]{64}$' || die "the control centre sent a bad checksum"

older() {  # A B: A is older than B
  a1=${1%%.*}; r=${1#*.}; a2=${r%%.*}; a3=${r#*.}
  b1=${2%%.*}; r=${2#*.}; b2=${r%%.*}; b3=${r#*.}
  [ "$a1" -lt "$b1" ] || { [ "$a1" -eq "$b1" ] && { [ "$a2" -lt "$b2" ] || { [ "$a2" -eq "$b2" ] && [ "$a3" -lt "$b3" ]; }; }; }
}
older "$VERSION" "$MIN_VERSION" && die "the control centre offers $VERSION, older than this installer ($MIN_VERSION); not installing"

fetch "$SERVER/agent-api/v1/download/$VERSION/$ARCH" "$TMP/cybercop-agent" || die "download failed"
GOT=$(sha256sum "$TMP/cybercop-agent" | cut -d' ' -f1)
[ "$GOT" = "$SUM" ] || die "checksum mismatch, not installing"

# --- signature: openssl 3, or python3-cryptography (RHEL 8 family: OpenSSL 1.1.1 cannot check Ed25519) ------------
printf '%s\n%s\n%s\n%s' "$PREFIX" "$VERSION" "$ARCH" "$GOT" > "$TMP/message"
printf '%s' "$SIG" > "$TMP/sig.b64"

PY=""
find_python() {
  for p in /usr/libexec/platform-python python3; do
    if command -v "$p" >/dev/null 2>&1 && "$p" -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey' 2>/dev/null; then
      PY="$p"; return 0
    fi
  done
  return 1
}
VERIFIER=""
if command -v openssl >/dev/null 2>&1 && openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
  VERIFIER=openssl
  openssl base64 -d -A -in "$TMP/sig.b64" -out "$TMP/sig" 2>/dev/null || die "bad signature encoding"
elif find_python; then
  VERIFIER=python
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  PM=$(command -v dnf || command -v yum)
  say "To check the signature of the agent this system needs the package python3-cryptography from your"
  OSSL=$(openssl version 2>/dev/null | cut -d' ' -f2)
  if [ -n "$OSSL" ]; then WHY="its OpenSSL $OSSL cannot check Ed25519 signatures"; else WHY="it has no OpenSSL 3"; fi
  say "distribution's own repository: $WHY."
  say "Nothing else is installed or changed for this; you can remove the package later."
  if [ "$AGREE_PKG" = no ]; then
    if ( : < /dev/tty ) 2>/dev/null; then
      printf 'cybercop-agent: install python3-cryptography now? [y/N] ' > /dev/tty
      read -r answer < /dev/tty || answer=""
      case "$answer" in y|Y|yes|YES|Yes) AGREE_PKG=yes ;; esac
    fi
  fi
  [ "$AGREE_PKG" = yes ] || die "not installing: without python3-cryptography the signature cannot be checked. Install it yourself (sudo $PM install python3-cryptography) or run the installer again with --install-python3-cryptography"
  "$PM" -q -y install python3-cryptography >/dev/null || die "could not install python3-cryptography"
  find_python || die "python3-cryptography is installed but cannot be used; not installing"
  VERIFIER=python
else
  die "cannot check the signature: needs OpenSSL 3 or python3 with the cryptography module; not installing"
fi

verify_key() {  # base64-public-key -> 0 if the signature verifies
  if [ "$VERIFIER" = openssl ]; then
    printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA%s\n-----END PUBLIC KEY-----\n' "$1" > "$TMP/key.pem"
    openssl pkeyutl -verify -pubin -inkey "$TMP/key.pem" -rawin -in "$TMP/message" -sigfile "$TMP/sig" >/dev/null 2>&1
  else
    "$PY" -c '
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
key = Ed25519PublicKey.from_public_bytes(base64.b64decode(sys.argv[1]))
key.verify(base64.b64decode(open(sys.argv[2]).read()), open(sys.argv[3], "rb").read())
' "$1" "$TMP/sig.b64" "$TMP/message" >/dev/null 2>&1
  fi
}
SIGNED_BY=""
for entry in $RELEASE_KEYS; do
  name=${entry%%:*}; key=${entry#*:}
  echo "$key" | grep -Eq '^[A-Za-z0-9+/]{43}=$' || continue
  if verify_key "$key"; then SIGNED_BY="$name"; break; fi
done
[ -n "$SIGNED_BY" ] || die "the signature of $VERSION does not match the release keys; not installing"
say "version $VERSION, signature checked ($SIGNED_BY key)"

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
# restart, not just start: on a reinstall over a running agent the old process would keep running the old binary
systemctl enable cybercop-agent cybercop-agent-update.path >/dev/null 2>&1
systemctl restart cybercop-agent
systemctl start cybercop-agent-update.path
say "installed $VERSION; the first inventory appears in the control centre within a few minutes"
