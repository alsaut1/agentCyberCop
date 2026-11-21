#!/bin/sh
# Build a release for the control centre to serve: dist/releases/<version>/{Linux and Windows files, install.sh,
# manifest.json}. Signing (by the maintainer, offline) is added on top of this with dist/add-signature.py, one line per
# file. dist/releases/current is NOT changed here: a version becomes current only after it is signed and tagged.
set -eu
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
cargo build --release --locked --target x86_64-unknown-linux-musl --bin cybercop-agent
cargo xwin build --release --locked --target x86_64-pc-windows-msvc --bin cybercop-agent
OUT=dist/releases/$VERSION
mkdir -p "$OUT"
cp target/x86_64-unknown-linux-musl/release/cybercop-agent "$OUT/cybercop-agent-x86_64"
cp target/x86_64-pc-windows-msvc/release/cybercop-agent.exe "$OUT/cybercop-agent-windows-x86_64.exe"
cp dist/install.sh "$OUT/install.sh"
L=$(sha256sum "$OUT/cybercop-agent-x86_64" | cut -d' ' -f1)
W=$(sha256sum "$OUT/cybercop-agent-windows-x86_64.exe" | cut -d' ' -f1)
printf '{"version": "%s", "files": {"x86_64": {"file": "cybercop-agent-x86_64", "sha256": "%s"}, "windows-x86_64": {"file": "cybercop-agent-windows-x86_64.exe", "sha256": "%s"}}}\n' "$VERSION" "$L" "$W" > "$OUT/manifest.json"
echo "release $VERSION"
echo "  x86_64          $L"
echo "  windows-x86_64  $W"
