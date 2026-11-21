#!/bin/sh
# Installer check in containers (podman), with the public TEST key only — never with release keys.
# Serves fake releases over local HTTPS and runs dist/install.sh on Debian 12, Ubuntu 22.04/24.04, Rocky 9 and
# AlmaLinux 8 (OpenSSL 1.1.1: python3-cryptography, installed only with the user's consent). systemd is stubbed and
# the "agent" is a signed shell script, so this checks the installer, not the agent.
#
#   tools/test-install/run.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
W=$(mktemp -d); trap 'kill $SRV 2>/dev/null || true; rm -rf "$W"' EXIT
cd "$ROOT" && cargo build -q --release --bin cybercop-agent-sign && SIGN="$ROOT/target/release/cybercop-agent-sign"
cd "$W"; cp "$HERE"/srv.py "$HERE"/cases.sh "$HERE"/el8.sh .
printf '\007%.0s' $(seq 32) > test.key          # secret half of release::TEST_KEY (public on purpose)
TEST_PUB=$($SIGN public test.key)
$SIGN keygen other.key > /dev/null; $SIGN keygen third.key > third.pub
printf '#!/bin/sh\necho "fake agent: $*"; [ "$1" = enroll ] && mkdir -p /var/lib/cybercop-agent && echo "{}" > /var/lib/cybercop-agent/agent.json; exit 0\n' > fake-agent
cp fake-agent fake-agent-tampered; echo "# tampered" >> fake-agent-tampered
mk() {  # case version file key|none
  d=www/$1/agent-api/v1; mkdir -p "$d/download/$2"; cp "$3" "$d/download/$2/x86_64"
  sha=$(sha256sum "$3" | cut -d' ' -f1)
  if [ "$4" = none ]; then echo "{\"error\": \"unsigned\", \"version\": \"$2\"}" > "$d/release"; return; fi
  sig=$($SIGN sign "$4" "$2" "$3" | sed 's/.*"signature": "\([^"]*\)".*/\1/')
  echo "{\"version\": \"$2\", \"arch\": \"x86_64\", \"sha256\": \"$sha\", \"signature\": \"$sig\"}" > "$d/release"
}
mk good 0.1.0 fake-agent test.key
mk foreign 0.1.0 fake-agent other.key
mk unsigned 0.1.0 fake-agent none
mk old 0.0.9 fake-agent test.key
mk tampered 0.1.0 fake-agent test.key; cp fake-agent-tampered www/tampered/agent-api/v1/download/0.1.0/x86_64
d=www/swapped/agent-api/v1; mkdir -p $d/download/0.1.0; cp fake-agent-tampered $d/download/0.1.0/x86_64
sed "s/\"sha256\": \"[0-9a-f]*\"/\"sha256\": \"$(sha256sum fake-agent-tampered | cut -d' ' -f1)\"/" www/good/agent-api/v1/release > $d/release
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.crt -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null
# main: an unrelated key, spare: the test key — so the spare key is checked too
sed "s|^RELEASE_KEYS=\"\"|RELEASE_KEYS=\"main:$(tr -d '\n' < third.pub) spare:$TEST_PUB\"|" "$ROOT/dist/install.sh" > install-test.sh
cp "$ROOT/dist/install.sh" install-nokeys.sh
python3 srv.py www srv.crt srv.key & SRV=$!; sleep 1
for img in docker.io/library/debian:12 docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04 docker.io/rockylinux/rockylinux:9; do
  case $img in *rocky*) prep='dnf -q -y install openssl >/dev/null 2>&1';; *) prep='apt-get -qq update >/dev/null && apt-get -qq install -y curl openssl ca-certificates >/dev/null 2>&1';; esac
  echo "== $img"; podman run --rm --network host -v "$W:/t:ro,Z" "$img" sh -c "$prep; sh /t/cases.sh" 2>&1 | grep -v level=
done
echo "== docker.io/library/almalinux:8"; podman run --rm --network host -v "$W:/t:ro,Z" docker.io/library/almalinux:8 sh /t/el8.sh 2>&1 | grep -v level=
