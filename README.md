# cybercop-agent

The server agent of HT CYBERCOP (the "Watcher"). It runs on a Linux server, collects an inventory and sends it to the
control centre over HTTPS. It only reads and reports: it never changes anything on the server and opens no ports.

## What it collects

- operating system and kernel versions;
- installed packages with versions (dpkg or rpm), including the source package — the control centre matches them
  against the security advisories of the distribution itself (with [Trivy](https://github.com/aquasecurity/trivy));
- running services, listening ports, Docker images (only if the agent user is added to the `docker` group);
- versions of site engines (WordPress with plugins, Joomla, Drupal);
- signs of a break-in: new users, new SSH keys (fingerprints only), new scheduled tasks, new listening ports.

## What it never collects

File contents, databases, passwords, private keys, traffic.

## Install

Take the installer from this repository, pinned to a release tag, and run it with the one-time code from the
control centre:

    curl -fsSL https://raw.githubusercontent.com/alsaut1/agentCyberCop/vX.Y.Z/dist/install.sh | sudo sh -s -- CODE

Compare the command shown in the control centre with this one: the installer must come from this repository, not
from the control centre. Only the version number, checksum and signature are taken from the control centre. The
installer downloads the agent, computes its SHA-256 itself and installs it only if

- the Ed25519 signature verifies with one of the release keys written in `dist/install.sh` (main and spare); the
  maintainer signs releases offline, the control centre has no signing key;
- the version is not older than the installer's own (`MIN_VERSION`), so an old signed version cannot be pushed.

The signature is checked with `openssl` (OpenSSL 3: Debian 12+, Ubuntu 22.04+, RHEL 9 family). On the RHEL 8 family
OpenSSL 1.1.1 cannot check Ed25519, so the installer needs `python3-cryptography` from the distribution's own
repository. It explains why and installs it only after you agree (a question in the terminal, or
`--install-python3-cryptography` in advance); without your consent it stops.

Remove the agent: `sudo sh install.sh --uninstall`, then revoke it in the control centre.

The installer checks can be run in containers with the public test key: `tools/test-install/run.sh` (podman).

## Build

    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl

The result is one static file without dependencies.

    cybercop-agent inventory   # print the inventory as JSON, nothing is sent

## License

Apache License 2.0, see `LICENSE`.
