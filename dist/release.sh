#!/bin/sh
# Build a release for the control centre to serve: dist/releases/<version>/{binary, install.sh, manifest.json} and
# dist/releases/current. Signing (by the maintainer, offline) is added on top of this.
set -eu
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
cargo build --release --locked --target x86_64-unknown-linux-musl
OUT=dist/releases/$VERSION
mkdir -p "$OUT"
cp target/x86_64-unknown-linux-musl/release/cybercop-agent "$OUT/cybercop-agent-x86_64"
cp dist/install.sh "$OUT/install.sh"
SUM=$(sha256sum "$OUT/cybercop-agent-x86_64" | cut -d' ' -f1)
printf '{"version": "%s", "files": {"x86_64": {"file": "cybercop-agent-x86_64", "sha256": "%s"}}}\n' "$VERSION" "$SUM" > "$OUT/manifest.json"
echo "$VERSION" > dist/releases/current
echo "release $VERSION: $SUM"
