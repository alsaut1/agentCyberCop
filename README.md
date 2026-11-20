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

## Build

    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl

The result is one static file without dependencies.

    cybercop-agent inventory   # print the inventory as JSON, nothing is sent

## License

Apache License 2.0, see `LICENSE`.
