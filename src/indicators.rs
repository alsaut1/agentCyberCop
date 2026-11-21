//! Signs of a break-in, sent every 15 minutes: users, SSH keys, scheduled tasks, listening ports. The control centre
//! remembers the first report as the baseline and raises an alarm on anything new.
//!
//! Nothing secret leaves the server: users without password hashes, SSH keys as fingerprints only (no comments),
//! scheduled tasks as file, schedule, program name and a hash of the line — never the full command, which may contain
//! passwords.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Serialize, Debug)]
pub struct Indicators {
    pub schema: u32,
    pub collected_at: u64,
    pub users: Vec<User>,
    pub ssh_keys: Vec<SshKey>,
    pub cron: Vec<CronEntry>,
    pub timers: Vec<String>,
    pub ports: Vec<crate::inventory::ports::Port>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub shell: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct SshKey {
    pub user: String,
    pub kind: String,
    pub fingerprint: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct CronEntry {
    pub file: String,
    pub schedule: String,
    pub program: String,
    pub id: String,
}

pub fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7).then(|| User { name: f[0].into(), uid: f[2].parse().unwrap_or(u32::MAX), shell: f[6].into() })
        })
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// One authorized_keys line → (type, "SHA256:…" fingerprint as `ssh-keygen -l` prints it). Options before the key
/// type are skipped; the comment is dropped.
pub fn key_fingerprint(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let i = parts.iter().position(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-") || p.starts_with("sk-"))?;
    let blob = B64.decode(parts.get(i + 1)?).ok()?;
    let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
    Some((parts[i].to_string(), format!("SHA256:{fp}")))
}

fn ssh_keys(users: &[User], passwd: &str) -> Vec<SshKey> {
    let mut out = Vec::new();
    for l in passwd.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 || !users.iter().any(|u| u.name == f[0]) {
            continue;
        }
        for file in ["authorized_keys", "authorized_keys2"] {
            let path = Path::new(f[5]).join(".ssh").join(file);
            let Ok(text) = fs::read_to_string(&path) else { continue };
            for line in text.lines() {
                if let Some((kind, fingerprint)) = key_fingerprint(line) {
                    out.push(SshKey { user: f[0].into(), kind, fingerprint });
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.user, &a.fingerprint).cmp(&(&b.user, &b.fingerprint)));
    out.dedup();
    out
}

/// Cron line → entry. `system` files (/etc/crontab, /etc/cron.d) have a user field after the schedule.
pub fn parse_cron(file: &str, text: &str, system: bool) -> Vec<CronEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let first = l.split_whitespace().next().unwrap_or("");
        if first.contains('=') && !first.starts_with('@') {
            continue; // VAR=value
        }
        let fields: Vec<&str> = l.split_whitespace().collect();
        let (schedule, rest) = if first.starts_with('@') { (first.to_string(), &fields[1..]) } else if fields.len() > 5 {
            (fields[..5].join(" "), &fields[5..])
        } else {
            continue;
        };
        let rest = if system && !rest.is_empty() { &rest[1..] } else { rest };
        let program = rest.first().map(|p| p.rsplit('/').next().unwrap_or(p).to_string()).unwrap_or_default();
        out.push(CronEntry { file: file.into(), schedule, program, id: sha256_hex(l.as_bytes())[..16].to_string() });
    }
    out
}

fn cron() -> Vec<CronEntry> {
    let mut out = Vec::new();
    if let Ok(t) = fs::read_to_string("/etc/crontab") {
        out.extend(parse_cron("/etc/crontab", &t, true));
    }
    for (dir, system) in [("/etc/cron.d", true), ("/var/spool/cron/crontabs", false), ("/var/spool/cron", false)] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        files.sort();
        for p in files {
            if let Ok(t) = fs::read_to_string(&p) {
                out.extend(parse_cron(&p.to_string_lossy(), &t, system));
            }
        }
    }
    for dir in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let id = fs::read(e.path()).map(|d| sha256_hex(&d)[..16].to_string()).unwrap_or_default();
            out.push(CronEntry { file: dir.into(), schedule: dir.trim_start_matches("/etc/cron.").into(), program: name, id });
        }
    }
    out
}

fn timers() -> Vec<String> {
    let out = std::process::Command::new("systemctl")
        .args(["list-timers", "--all", "--no-legend", "--plain", "--no-pager"])
        .output();
    let Ok(o) = out else { return Vec::new() };
    let mut t: Vec<String> = String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .filter(|w| w.ends_with(".timer"))
        .map(String::from)
        .collect();
    t.sort();
    t.dedup();
    t
}

pub fn collect() -> Indicators {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let users = parse_passwd(&passwd);
    let keys = ssh_keys(&users, &passwd);
    Indicators {
        schema: 1,
        collected_at: crate::inventory::now(),
        users,
        ssh_keys: keys,
        cron: cron(),
        timers: timers(),
        ports: crate::inventory::ports::collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd() {
        let u = parse_passwd("root:x:0:0:root:/root:/bin/bash\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n");
        assert_eq!(u[0], User { name: "root".into(), uid: 0, shell: "/bin/bash".into() });
    }

    #[test]
    fn fingerprint_like_ssh_keygen() {
        // ssh-keygen -lf: SHA256:… for this test key.
        let line = r#"from="192.0.2.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host"#;
        let (kind, fp) = key_fingerprint(line).unwrap();
        assert_eq!(kind, "ssh-ed25519");
        assert!(fp.starts_with("SHA256:") && !fp.contains("user@host") && !fp.ends_with('='));
        assert_eq!(key_fingerprint("# comment"), None);
    }

    #[test]
    fn cron_lines_without_commands() {
        let e = parse_cron("/etc/cron.d/x", "SHELL=/bin/sh\n# c\n*/5 * * * * root /usr/bin/curl -u admin:secret http://x\n@reboot root /opt/a.sh\n", true);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].schedule.as_str(), e[0].program.as_str()), ("*/5 * * * *", "curl"));
        assert_eq!(e[1].program, "a.sh");
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("secret") && !json.contains("admin"));
        let u = parse_cron("/var/spool/cron/crontabs/alice", "0 3 * * * /opt/backup/run.sh --pw x\n", false);
        assert_eq!(u[0].program, "run.sh");
    }
}
