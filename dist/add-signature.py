#!/usr/bin/env python3
"""Add the signature line printed by `cybercop-agent-sign sign` (on the maintainer's laptop) to a release manifest.
The signature is public; the secret key never leaves the laptop. The line is checked against the release file first.

    dist/add-signature.py dist/releases/<version> '<line from cybercop-agent-sign>'
"""
import hashlib
import json
import pathlib
import sys

rel = pathlib.Path(sys.argv[1])
line = json.loads(sys.argv[2])
manifest = json.loads((rel / "manifest.json").read_text())
entry = manifest["files"][line["arch"]]
digest = hashlib.sha256((rel / entry["file"]).read_bytes()).hexdigest()
if line["version"] != manifest["version"] or line["sha256"] != digest or entry["sha256"] != digest:
    sys.exit("the signature is for another file or version")
manifest.setdefault("signatures", {})[line["arch"]] = line["signature"]
(rel / "manifest.json").write_text(json.dumps(manifest) + "\n")
print(f"signature added for {manifest['version']} {line['arch']}")
