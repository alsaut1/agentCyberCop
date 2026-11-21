#!/bin/sh
# Windows installer check on a test Windows machine (reached over SSH), with the public TEST key only — never with
# release keys. Builds a development agent (trusts the test key, allows http to 127.0.0.1), prepares fake releases,
# copies everything to the machine and runs cases.ps1 there against a local HTTP server (srv.ps1).
#
#   tools/test-install/windows/run.sh Administrator@<test machine>
set -eu
HOST=${1:?usage: run.sh user@windows-host}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../../.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cd "$ROOT"
cargo build -q --release --bin cybercop-agent-sign && SIGN="$ROOT/target/release/cybercop-agent-sign"
cargo xwin build -q --release --features dev --target x86_64-pc-windows-msvc --bin cybercop-agent
AGENT="$ROOT/target/x86_64-pc-windows-msvc/release/cybercop-agent.exe"
cd "$W"; mkdir stand; cp "$HERE"/srv.ps1 "$HERE"/cases.ps1 "$ROOT"/tools/test-install/ed25519-vectors.ps1 stand/
printf '\007%.0s' $(seq 32) > test.key          # secret half of release::TEST_KEY (public on purpose)
TEST_PUB=$($SIGN public test.key)
$SIGN keygen other.key > /dev/null; $SIGN keygen third.key > third.pub
cp "$AGENT" agent.exe; cp agent.exe agent-tampered.exe; printf 'tampered' >> agent-tampered.exe
mk() {  # case version file key|none
  d=stand/www/$1/agent-api/v1; mkdir -p "$d/download/$2"; cp "$3" "$d/download/$2/windows-x86_64"
  [ "$4" = none ] && return
  $SIGN sign "$4" "$2" "$3" windows-x86_64 > "$d/release"
}
mk good 0.2.0 agent.exe test.key
mk foreign 0.2.0 agent.exe other.key
mk unsigned 0.2.0 agent.exe none
mk old 0.1.9 agent.exe test.key
mk tampered 0.2.0 agent.exe test.key; cp agent-tampered.exe stand/www/tampered/agent-api/v1/download/0.2.0/windows-x86_64
d=stand/www/swapped/agent-api/v1; mkdir -p $d/download/0.2.0; cp agent-tampered.exe $d/download/0.2.0/windows-x86_64
sed "s/\"sha256\": \"[0-9a-f]*\"/\"sha256\": \"$(sha256sum agent-tampered.exe | cut -d' ' -f1)\"/" stand/www/good/agent-api/v1/release > $d/release
# Self-update: a different file (the same program with bytes appended) signed as 9.9.9 with the test key.
d=stand/www/good/agent-api/v1; mkdir -p $d/download/9.9.9; cp agent-tampered.exe $d/download/9.9.9/windows-x86_64
$SIGN sign test.key 9.9.9 agent-tampered.exe windows-x86_64 | python3 -c 'import json,sys; o=json.load(sys.stdin); print(json.dumps({"update": {"version": o["version"], "url": "http://127.0.0.1:8480/good/agent-api/v1/download/9.9.9/windows-x86_64", "sha256": o["sha256"], "signature": o["signature"]}}))' > stand/offer-good.json
$SIGN sign other.key 9.9.9 agent-tampered.exe windows-x86_64 | python3 -c 'import json,sys; o=json.load(sys.stdin); print(json.dumps({"update": {"version": o["version"], "url": "http://127.0.0.1:8480/good/agent-api/v1/download/9.9.9/windows-x86_64", "sha256": o["sha256"], "signature": o["signature"]}}))' > stand/offer-foreign.json
sha256sum agent-tampered.exe | cut -d' ' -f1 > stand/new.sha256
# Linux-signed file offered to Windows: the signature names x86_64, the installer asks for windows-x86_64.
mk linuxsig 0.2.0 agent.exe test.key; $SIGN sign test.key 0.2.0 agent.exe x86_64 | sed 's/"arch": "x86_64"/"arch": "windows-x86_64"/' > stand/www/linuxsig/agent-api/v1/release
# The real keys and MIN version are replaced by test ones, and http to 127.0.0.1 is allowed for the local server;
# the rest of the installer is used as is.
sed -e "s|^\$ReleaseKeys = @(.*)|\$ReleaseKeys = @(\"main:$(tr -d '\n' < third.pub)\", \"spare:$TEST_PUB\")|" \
    -e 's|^\$MinVersion = ".*"|$MinVersion = "0.2.0"|' \
    -e 's|if (-not \$Server.StartsWith("https://"))|if (-not ($Server.StartsWith("https://") -or $Server.StartsWith("http://127.0.0.1:")))|' \
    "$ROOT/dist/install.ps1" > stand/install-test.ps1
sed -e 's|^\$ReleaseKeys = @(.*)|$ReleaseKeys = @()|' -e 's|^\$MinVersion = ".*"|$MinVersion = "0.2.0"|' \
    -e 's|if (-not \$Server.StartsWith("https://"))|if (-not ($Server.StartsWith("https://") -or $Server.StartsWith("http://127.0.0.1:")))|' \
    "$ROOT/dist/install.ps1" > stand/install-nokeys.ps1
grep -q "spare:$TEST_PUB" stand/install-test.ps1 && grep -q '^\$ReleaseKeys = @()' stand/install-nokeys.ps1 || { echo "substitution failed"; exit 1; }
ssh -o BatchMode=yes "$HOST" 'powershell -NoProfile -Command "Remove-Item -Recurse -Force C:\cc-stand -ErrorAction SilentlyContinue; exit 0"'
scp -q -r stand "$HOST":C:/cc-stand
ssh -o BatchMode=yes "$HOST" 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\cc-stand\ed25519-vectors.ps1 C:\cc-stand\install-test.ps1 & powershell -NoProfile -ExecutionPolicy Bypass -File C:\cc-stand\cases.ps1'
ssh -o BatchMode=yes "$HOST" 'powershell -NoProfile -Command "Remove-Item -Recurse -Force C:\cc-stand"'
