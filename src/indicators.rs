//! Signs of a break-in, sent every 15 minutes: users (and who is in the sudo, wheel or admin group), SSH keys,
//! scheduled tasks, systemd timers and services, users' own services, listening ports, and when the package database
//! last changed. The control centre remembers the first report as the baseline and raises an alarm on anything new or
//! changed.
//!
//! Nothing secret leaves the server: users without password hashes, SSH keys as fingerprints only (no comments),
//! scheduled tasks and services as file, schedule, user, program and a hash of the whole command line — never the
//! arguments, which may contain passwords.

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
    pub agent: crate::update::AgentSelf,
    pub users: Vec<User>,
    pub ssh_keys: Vec<SshKey>,
    pub cron: Vec<CronEntry>,
    pub timers: Vec<Timer>,
    pub services: Vec<crate::systemd::Service>,
    pub user_services: Vec<crate::systemd::UserService>,
    /// When the package database (dpkg or rpm) last changed, Unix seconds; 0 if unknown.
    pub packages_changed_at: u64,
    pub ports: Vec<crate::inventory::ports::Port>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Timer {
    pub name: String,
    /// The unit the timer starts.
    pub unit: String,
}

/// Groups whose members may become root with sudo.
pub const ADMIN_GROUPS: [&str; 3] = ["sudo", "wheel", "admin"];

#[derive(Serialize, Debug, PartialEq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
    /// Member of sudo, wheel or admin (also as the primary group).
    pub admin: bool,
    pub admin_groups: Vec<String>,
    #[serde(skip)]
    pub gid: u32,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct SshKey {
    pub user: String,
    /// The authorized_keys file: users sharing a home (root and operator on RHEL) share the same keys.
    pub file: String,
    pub kind: String,
    pub fingerprint: String,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct CronEntry {
    pub file: String,
    pub schedule: String,
    pub program: String,
    /// Program as written (first word of the command), or the script's full path.
    pub path: String,
    /// User the line runs as: the user field of /etc/crontab and /etc/cron.d, the owner of a user crontab, root for
    /// the cron.daily-style folders.
    pub user: String,
    pub id: String,
}

pub fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7).then(|| User {
                name: f[0].into(),
                uid: f[2].parse().unwrap_or(u32::MAX),
                home: f[5].into(),
                shell: f[6].into(),
                admin: false,
                admin_groups: Vec::new(),
                gid: f[3].parse().unwrap_or(u32::MAX),
            })
        })
        .collect()
}

/// /etc/group → mark members of sudo, wheel and admin (listed members and users with that primary group).
pub fn mark_admins(users: &mut [User], group: &str) {
    for l in group.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 4 || !ADMIN_GROUPS.contains(&f[0]) {
            continue;
        }
        let gid: u32 = f[2].parse().unwrap_or(u32::MAX - 1);
        let members: Vec<&str> = f[3].split(',').map(str::trim).filter(|m| !m.is_empty()).collect();
        for u in users.iter_mut() {
            if (members.contains(&u.name.as_str()) || u.gid == gid) && !u.admin_groups.iter().any(|g| g == f[0]) {
                u.admin = true;
                u.admin_groups.push(f[0].to_string());
            }
        }
    }
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
                    out.push(SshKey { user: f[0].into(), file: path.display().to_string(), kind, fingerprint });
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.user, &a.fingerprint).cmp(&(&b.user, &b.fingerprint)));
    out.dedup();
    out
}

/// Cron line → entry. `system` files (/etc/crontab, /etc/cron.d) have a user field after the schedule; a user crontab
/// runs as `owner`.
pub fn parse_cron(file: &str, text: &str, system: bool, owner: &str) -> Vec<CronEntry> {
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
        let user = if system { rest.first().copied().unwrap_or("").to_string() } else { owner.to_string() };
        let rest = if system && !rest.is_empty() { &rest[1..] } else { rest };
        // A variable before the command (`PASS=x /opt/run`) may hold a secret: then no program at all.
        let path = rest.first().filter(|p| !p.contains('=')).map(|p| p.to_string()).unwrap_or_default();
        let program = path.rsplit('/').next().unwrap_or("").to_string();
        out.push(CronEntry { file: file.into(), schedule, program, path, user, id: sha256_hex(l.as_bytes())[..16].to_string() });
    }
    out
}

fn cron() -> Vec<CronEntry> {
    let mut out = Vec::new();
    if let Ok(t) = fs::read_to_string("/etc/crontab") {
        out.extend(parse_cron("/etc/crontab", &t, true, ""));
    }
    for (dir, system) in [("/etc/cron.d", true), ("/var/spool/cron/crontabs", false), ("/var/spool/cron", false)] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        files.sort();
        for p in files {
            if let Ok(t) = fs::read_to_string(&p) {
                let owner = if system { String::new() } else { p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default() };
                out.extend(parse_cron(&p.to_string_lossy(), &t, system, &owner));
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
            let path = e.path().display().to_string();
            out.push(CronEntry { file: dir.into(), schedule: dir.trim_start_matches("/etc/cron.").into(), program: name, path, user: "root".into(), id });
        }
    }
    out
}

/// `systemctl list-timers` lines → timers with the unit each one starts (the word after the timer).
pub fn parse_timers(text: &str) -> Vec<Timer> {
    let mut t: Vec<Timer> = text
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let i = w.iter().position(|x| x.ends_with(".timer"))?;
            Some(Timer { name: w[i].to_string(), unit: w.get(i + 1).map(|s| s.to_string()).unwrap_or_default() })
        })
        .collect();
    t.sort_by(|a, b| a.name.cmp(&b.name));
    t.dedup_by(|a, b| a.name == b.name);
    t
}

fn timers() -> Vec<Timer> {
    let out = std::process::Command::new("systemctl")
        .args(["list-timers", "--all", "--no-legend", "--plain", "--no-pager"])
        .output();
    let Ok(o) = out else { return Vec::new() };
    parse_timers(&String::from_utf8_lossy(&o.stdout))
}

/// Last change of the package database: dpkg's status file or the rpm database.
fn packages_changed_at() -> u64 {
    [
        "/var/lib/dpkg/status",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/rpm/Packages",
        "/usr/lib/sysimage/rpm/rpmdb.sqlite",
        "/usr/lib/sysimage/rpm/Packages",
    ]
    .iter()
    .filter_map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
    .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
    .map(|d| d.as_secs())
    .max()
    .unwrap_or(0)
}

pub fn collect() -> Indicators {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut users = parse_passwd(&passwd);
    mark_admins(&mut users, &fs::read_to_string("/etc/group").unwrap_or_default());
    let keys = ssh_keys(&users, &passwd);
    let homes: Vec<(String, String)> = users.iter().map(|u| (u.name.clone(), u.home.clone())).collect();
    Indicators {
        schema: 2,
        collected_at: crate::inventory::now(),
        agent: crate::update::agent_self(),
        ssh_keys: keys,
        cron: cron(),
        timers: timers(),
        services: crate::systemd::services(),
        user_services: crate::systemd::user_services(&homes),
        packages_changed_at: packages_changed_at(),
        users,
        ports: crate::inventory::ports::collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd() {
        let mut u = parse_passwd("root:x:0:0:root:/root:/bin/bash\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nann:x:1001:1001::/home/ann:/bin/bash\nbob:x:1002:10::/home/bob:/bin/sh\n");
        assert_eq!((u[0].name.as_str(), u[0].uid, u[0].home.as_str(), u[0].shell.as_str()), ("root", 0, "/root", "/bin/bash"));
        mark_admins(&mut u, "root:x:0:\nsudo:x:27:ann,other\nwheel:x:10:\nadm:x:4:bin\n");
        assert_eq!((u[2].admin, u[2].admin_groups.clone()), (true, vec!["sudo".to_string()]));
        assert_eq!((u[3].admin, u[3].admin_groups.clone()), (true, vec!["wheel".to_string()]));   // primary group
        assert!(!u[0].admin && !u[1].admin);
        assert!(!serde_json::to_string(&u[0]).unwrap().contains("gid"));
    }

    #[test]
    fn timers_with_units() {
        let t = parse_timers("Mon 2026-01-05 00:00:00 UTC 5h left Sun 2026-01-04 00:00:00 UTC 18h ago logrotate.timer logrotate.service\n\
- - - - backup.timer backup.service\n");
        assert_eq!(t, vec![Timer { name: "backup.timer".into(), unit: "backup.service".into() },
                           Timer { name: "logrotate.timer".into(), unit: "logrotate.service".into() }]);
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
        let e = parse_cron("/etc/cron.d/x", "SHELL=/bin/sh\n# c\n*/5 * * * * root /usr/bin/curl -u admin:secret http://x\n@reboot www-data /opt/a.sh\n* * * * * root PASS=x /opt/b\n", true, "");
        assert_eq!(e.len(), 3);
        assert_eq!((e[0].schedule.as_str(), e[0].program.as_str(), e[0].path.as_str(), e[0].user.as_str()), ("*/5 * * * *", "curl", "/usr/bin/curl", "root"));
        assert_eq!((e[1].program.as_str(), e[1].user.as_str()), ("a.sh", "www-data"));
        assert_eq!((e[2].program.as_str(), e[2].path.as_str()), ("", ""));
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("secret") && !json.contains("admin") && !json.contains("PASS"));
        let u = parse_cron("/var/spool/cron/crontabs/someone", "0 3 * * * /opt/backup/run.sh --pw x\n", false, "someone");
        assert_eq!((u[0].program.as_str(), u[0].user.as_str()), ("run.sh", "someone"));
    }
}
