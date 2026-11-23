# cybercop-agent

The server agent of HT CYBERCOP (the "Watcher"). It runs on a Linux or Windows server, collects an inventory and sends
it to the control centre over HTTPS. It only reads and reports: it never changes anything on the server and opens no
ports.

## What it collects

Linux:

- operating system and kernel versions;
- installed packages with versions (dpkg or rpm), including the source package — the control centre matches them
  against the security advisories of the distribution itself (with [Trivy](https://github.com/aquasecurity/trivy));
- running services, listening ports, Docker images (only if the agent user is added to the `docker` group);
- versions of site engines (WordPress with plugins, Joomla, Drupal);
- signs of a break-in: new users (name, uid, home folder, shell), new SSH keys (fingerprint and the `authorized_keys`
  file, never the key itself or its comment), new scheduled tasks, new listening ports.

Windows:

- system version and build;
- installed programs (as «Programs and Features» lists them), services, listening ports with the owning process;
- missing system updates, asked from Windows itself (Windows Update, or the organisation's WSUS server if a policy
  says so); only the search runs, nothing is downloaded or installed. The control centre looks up which
  vulnerabilities each update fixes in Microsoft's Security Update Guide. For third-party programs only the list is
  kept;
- signs of a break-in: new users (and who is an administrator), new Task Scheduler tasks, new services, new
  listening ports. Tasks and services as name, program path and a hash of the whole command, never the arguments:
  the control centre sees that a task or a service now runs another program, other arguments or under another
  account.

Both: the server's clock in each heartbeat (so the control centre can tell when it is off), the path of the agent's
own file and its SHA-256, so the control centre can tell the agent's own user,
service and task (the installer created them, the file matches a signed release) from look-alikes.

Windows also: installed application compatibility databases (`sdbinst`): GUID, path, SHA-256 and what is inside —
which programs they apply to, which shims, whether they make programs load other code.

Password guessing (on Linux SSH, mail — Postfix, Dovecot, Exim — and FTP — vsftpd, ProFTPD, Pure-FTPd; on Windows
RDP and SSH): the agent reads only the new log records since its last pass (the systemd journal, or the syslog files;
the servers' own logs — Exim's main log, ProFTPD's and vsftpd's logs — and wtmp for ProFTPD's logins; on Windows the
Security, RDP and OpenSSH event logs), keeps counters — not log lines — for 48 hours and every 15 minutes sends a
summary: per service, attempts, the number of distinct addresses and user names, logins after a series of failures,
locked accounts. A login after a series of failures counts only from a network (IPv4 /24, IPv6 /64) the account has
not logged in from within 90 days; these networks stay on the server, in the agent's state folder. To know them from
the start, on its first start the agent reads once the old logs still on the server (rotated and `.gz` ones too) for
successful logins only. Addresses with 10 or more failures within an hour, and no successful login from them, are
sent for the shared list of attacking addresses. Addresses with counts and the user names tried (for mail, sending
and receiving apart) are sent only when the server's owner asks for them in the control centre. A server that is not
installed costs nothing: its files do not exist and the journal filter does not match. The time of a record is taken
from the record itself (its own zone, or the server's zone when the line has none) if it is within the last hour,
otherwise the time of the pass.

vsftpd with its default settings on Red Hat-like systems writes no line of its own about logins, and in the PAM line
it writes the client's host name instead of its address when the address has one; such attempts are counted in the
summary without an address (no series, no shared list). With `dual_log_enable=YES` (or `xferlog_std_format=NO`) vsftpd
writes its own log with addresses and logins; on Red Hat-like systems `reverse_lookup_enable=NO` keeps the address in
the PAM line (logins are still not seen there).
The agent tells the control centre when vsftpd is installed without its own log (by its settings), and the client
sees a hint there.

Measured cost on small servers: a pass 11–30 ms of processor time, no disk reads, 2–3 KB of state; the one-time
reading of old logs about 0.5 s for a few MB, and about 2 s of wall time for 3 million lines (320 MB of text).

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

## Install on Windows

Windows Server 2016, 2019, 2022 and 2025, 64-bit. Windows 10 and 11 are not supported. On a real machine only Windows
Server 2025 has been checked so far.

In PowerShell run as Administrator, with the one-time code from the control centre:

    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/alsaut1/agentCyberCop/vX.Y.Z/dist/install.ps1))) -Code CODE

As on Linux, the installer comes from this repository and checks the agent's SHA-256 and Ed25519 signature itself
with the release keys written in `dist/install.ps1`; the version must not be older than the installer's own
(`$MinVersion`). Windows has no built-in Ed25519, so the check is written out in the installer (RFC 8032) and tested
against the RFC test vectors and against signatures that must be refused: `tools/test-install/ed25519-vectors.ps1`.

What it installs:

- `C:\Program Files\CybercopAgent\cybercop-agent.exe`;
- the service `CybercopAgent`, under its own unprivileged account `NT SERVICE\CybercopAgent`: it talks to the control
  centre and downloads updates (download and check only);
- the scheduled task `CybercopAgent`, every 5 minutes as SYSTEM: collects what needs administrator rights (Windows
  Update, owners of listening ports, all scheduled tasks) and installs an update only after checking its signature
  again. It never uses the network;
- the state folder `C:\ProgramData\CybercopAgent`, readable only by SYSTEM, Administrators and the service account.

**The agent is not signed with a publisher (Authenticode) certificate**, so some antivirus programs may block or delete
it. Before installing, add both folders to the antivirus exclusions, for Microsoft Defender:

    Add-MpPreference -ExclusionPath "C:\Program Files\CybercopAgent","C:\ProgramData\CybercopAgent"

To check the file yourself after installation, compare its checksum with the one shown in the control centre next to
the command (it is also the `sha256` that `agent-api/v1/release?arch=windows-x86_64` returns):

    (Get-FileHash "C:\Program Files\CybercopAgent\cybercop-agent.exe").Hash

Remove the agent: the same command with `-Uninstall` instead of `-Code CODE`, then revoke it in the control centre.

The installer checks on a test Windows machine, with the public test key: `tools/test-install/windows/run.sh`.

## Build

    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl

The result is one static file without dependencies.

Windows, from Linux with [cargo-xwin](https://github.com/rust-cross/cargo-xwin) (Microsoft's compiler libraries; their
licence permits building open-source applications):

    rustup target add x86_64-pc-windows-msvc
    cargo xwin build --release --target x86_64-pc-windows-msvc

`dist/release.sh` builds both.

    cybercop-agent inventory   # print the inventory as JSON, nothing is sent

## License

Apache License 2.0, see `LICENSE`.
