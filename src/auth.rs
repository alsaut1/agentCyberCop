//! Password guessing (RDP and SSH): the agent reads only the new log records since its last pass, keeps counters
//! (not the log) for 48 hours and sends a summary: per service and 15-minute window — attempts, distinct addresses,
//! distinct user names, logins after a series of failures, locked accounts. Details (addresses with counts, and the
//! user names tried) go only when the client asks for them in the control centre. Addresses with 10 or more failures
//! within an hour, and no successful login from them, are sent separately for the shared list of attacking addresses.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const WINDOW: u64 = 900; // 15 minutes
pub const KEEP: u64 = 48 * 3600;
const HOUR: u64 = 3600;
const SERIES: u32 = 5; // failures within the hour before a login → «login after a series of failures»
const ATTACKER: u32 = 10; // failures within an hour → the address goes to the shared list
const MAX_IPS: usize = 20_000;
const MAX_USERS_PER_IP: usize = 30;
const MAX_SET: usize = 5_000;

/// One thing seen in a log.
#[derive(Debug, PartialEq, Clone)]
pub enum Seen {
    Failure { service: &'static str, ip: String, user: String },
    Success { service: &'static str, ip: String, user: String },
    Lockout { service: &'static str, user: String },
}

/// An OpenSSH log line (Linux journal or file, Windows OpenSSH/Operational) → what it says, if anything we count.
/// A connection with a non-existent user is counted once ("Invalid user"), each password tried for an existing user
/// once ("Failed password"); public key failures are normal (several keys tried) and not counted.
pub fn parse_sshd(msg: &str) -> Option<Seen> {
    let msg = msg.trim();
    if let Some(rest) = msg.strip_prefix("Invalid user ") {
        let (user, ip) = user_from(rest)?;
        return Some(Seen::Failure { service: "ssh", ip, user });
    }
    for prefix in ["Failed password for ", "Failed keyboard-interactive/pam for ", "Failed none for "] {
        if let Some(rest) = msg.strip_prefix(prefix) {
            if rest.starts_with("invalid user ") {
                return None; // already counted by its "Invalid user" line
            }
            let (user, ip) = user_from(rest)?;
            return Some(Seen::Failure { service: "ssh", ip, user });
        }
    }
    if let Some(rest) = msg.strip_prefix("Accepted ") {
        let rest = rest.split_once(" for ")?.1;
        let (user, ip) = user_from(rest)?;
        return Some(Seen::Success { service: "ssh", ip, user });
    }
    if msg.contains("pam_faillock(") && msg.contains("account temporarily locked") {
        let user = msg.split("for user ").nth(1)?.split_whitespace().next()?.to_string();
        return Some(Seen::Lockout { service: "ssh", user });
    }
    None
}

/// "NAME from ADDRESS port N ..." → (name, address). The name may be empty or contain spaces.
fn user_from(rest: &str) -> Option<(String, String)> {
    let i = rest.rfind(" from ")?;
    let user = rest[..i].trim().to_string();
    let ip = rest[i + 6..].split_whitespace().next()?.to_string();
    ip.parse::<std::net::IpAddr>().ok()?;
    Some((user.chars().take(64).collect(), ip))
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Win {
    pub attempts: u64,
    pub ips: BTreeSet<String>,
    pub users: BTreeSet<String>,
    pub success_after: u64,
    pub lockouts: u64,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Ip {
    pub service: String,
    pub first: u64,
    pub last: u64,
    pub attempts: u64,
    /// failures per hour (hour start → count), for «10 within an hour» and «5 before a login»
    pub hours: BTreeMap<u64, u32>,
    pub users: BTreeMap<String, u64>,
    pub success: u64, // last successful login from this address
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Event {
    pub id: String,
    pub kind: String, // success_after | lockout
    pub service: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ip: String,
    pub user: String,
    pub at: u64,
    pub failures: u32,
}

/// Counters kept on the server between passes (state folder). No log lines.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Counters {
    /// window start → service → counters
    pub windows: BTreeMap<u64, BTreeMap<String, Win>>,
    pub ips: BTreeMap<String, Ip>,
    pub events: Vec<Event>,
}

impl Counters {
    pub fn add(&mut self, seen: Seen, at: u64) {
        let start = at - at % WINDOW;
        let hour = at - at % HOUR;
        match seen {
            Seen::Failure { service, ip, user } => {
                let w = self.windows.entry(start).or_default().entry(service.into()).or_default();
                w.attempts += 1;
                if w.ips.len() < MAX_SET {
                    w.ips.insert(ip.clone());
                }
                if w.users.len() < MAX_SET {
                    w.users.insert(user.clone());
                }
                let e = self.ips.entry(ip).or_insert_with(|| Ip { service: service.into(), first: at, ..Default::default() });
                e.last = e.last.max(at);
                e.first = e.first.min(at);
                e.attempts += 1;
                *e.hours.entry(hour).or_default() += 1;
                if e.users.len() < MAX_USERS_PER_IP || e.users.contains_key(&user) {
                    *e.users.entry(user).or_default() += 1;
                }
            }
            Seen::Success { service, ip, user } => {
                let failures: u32 = self
                    .ips
                    .get(&ip)
                    .map(|e| e.hours.iter().filter(|(h, _)| **h + HOUR > at.saturating_sub(HOUR)).map(|(_, n)| *n).sum())
                    .unwrap_or(0);
                if let Some(e) = self.ips.get_mut(&ip) {
                    e.success = at;
                    if failures >= SERIES {
                        e.hours.clear(); // the series is reported; the next login needs a new series to alarm again
                    }
                }
                if failures >= SERIES {
                    self.windows.entry(start).or_default().entry(service.into()).or_default().success_after += 1;
                    self.event("success_after", service, &ip, &user, at, failures);
                }
            }
            Seen::Lockout { service, user } => {
                self.windows.entry(start).or_default().entry(service.into()).or_default().lockouts += 1;
                self.event("lockout", service, "", &user, at, 0);
            }
        }
    }

    fn event(&mut self, kind: &str, service: &str, ip: &str, user: &str, at: u64, failures: u32) {
        let id = crate::update::sha256_hex(format!("{kind}\x1f{service}\x1f{ip}\x1f{user}\x1f{at}").as_bytes())[..16].to_string();
        if !self.events.iter().any(|e| e.id == id) {
            self.events.push(Event { id, kind: kind.into(), service: service.into(), ip: ip.into(), user: user.into(), at, failures });
        }
    }

    /// Drop what is older than 48 hours; keep the address table bounded.
    pub fn prune(&mut self, now: u64) {
        let edge = now.saturating_sub(KEEP);
        self.windows.retain(|s, _| *s >= edge);
        self.events.retain(|e| e.at >= edge);
        self.ips.retain(|_, e| e.last >= edge || e.success >= edge);
        for e in self.ips.values_mut() {
            e.hours.retain(|h, _| *h >= edge);
        }
        if self.ips.len() > MAX_IPS {
            let mut by_last: Vec<(u64, String)> = self.ips.iter().map(|(k, e)| (e.last, k.clone())).collect();
            by_last.sort();
            for (_, k) in by_last.into_iter().take(self.ips.len() - MAX_IPS) {
                self.ips.remove(&k);
            }
        }
    }

    pub fn report(&self, platform: &str, now: u64, details: bool) -> Report {
        let since = now.saturating_sub(2 * HOUR);
        let windows = self
            .windows
            .range(since - since % WINDOW..)
            .flat_map(|(start, m)| {
                m.iter().map(move |(svc, w)| WinOut {
                    start: *start,
                    service: svc.clone(),
                    attempts: w.attempts,
                    ips: w.ips.len() as u64,
                    users: w.users.len() as u64,
                    success_after: w.success_after,
                    lockouts: w.lockouts,
                })
            })
            .collect();
        let attackers = self
            .ips
            .iter()
            .filter(|(_, e)| e.last >= since && e.success == 0 && e.hours.values().any(|n| *n >= ATTACKER))
            .map(|(ip, e)| Attacker { ip: ip.clone(), service: e.service.clone(), attempts: e.attempts, last: e.last })
            .collect();
        let events = self.events.iter().filter(|e| e.at + 24 * HOUR >= now).cloned().collect();
        Report {
            schema: 1,
            platform: platform.into(),
            collected_at: now,
            windows,
            events,
            attackers,
            details: details.then(|| self.details(now)),
        }
    }

    fn details(&self, now: u64) -> Details {
        let mut ips: Vec<IpOut> = self
            .ips
            .iter()
            .filter(|(_, e)| e.attempts > 0)
            .map(|(ip, e)| {
                let mut users: Vec<(String, u64)> = e.users.iter().map(|(u, n)| (u.clone(), *n)).collect();
                users.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                IpOut { ip: ip.clone(), service: e.service.clone(), attempts: e.attempts, first: e.first, last: e.last, success: e.success, users }
            })
            .collect();
        ips.sort_by(|a, b| b.attempts.cmp(&a.attempts).then(a.ip.cmp(&b.ip)));
        ips.truncate(200);
        let mut by_user: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
        for (ip, e) in &self.ips {
            for (u, n) in &e.users {
                let x = by_user.entry(u.clone()).or_default();
                x.0 += n;
                x.1.insert(ip.clone());
            }
        }
        let mut users: Vec<UserOut> =
            by_user.into_iter().map(|(name, (attempts, ips))| UserOut { name, attempts, ips: ips.len() as u64 }).collect();
        users.sort_by(|a, b| b.attempts.cmp(&a.attempts).then(a.name.cmp(&b.name)));
        users.truncate(200);
        Details { generated_at: now, since: now.saturating_sub(KEEP), ips, users }
    }
}

#[derive(Serialize, Debug)]
pub struct WinOut {
    pub start: u64,
    pub service: String,
    pub attempts: u64,
    pub ips: u64,
    pub users: u64,
    pub success_after: u64,
    pub lockouts: u64,
}

#[derive(Serialize, Debug)]
pub struct Attacker {
    pub ip: String,
    pub service: String,
    pub attempts: u64,
    pub last: u64,
}

#[derive(Serialize, Debug)]
pub struct IpOut {
    pub ip: String,
    pub service: String,
    pub attempts: u64,
    pub first: u64,
    pub last: u64,
    pub success: u64,
    pub users: Vec<(String, u64)>,
}

#[derive(Serialize, Debug)]
pub struct UserOut {
    pub name: String,
    pub attempts: u64,
    pub ips: u64,
}

#[derive(Serialize, Debug)]
pub struct Details {
    pub generated_at: u64,
    pub since: u64,
    pub ips: Vec<IpOut>,
    pub users: Vec<UserOut>,
}

#[derive(Serialize, Debug)]
pub struct Report {
    pub schema: u32,
    pub platform: String,
    pub collected_at: u64,
    pub windows: Vec<WinOut>,
    pub events: Vec<Event>,
    pub attackers: Vec<Attacker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Details>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_lines() {
        assert_eq!(
            parse_sshd("Invalid user admin from 203.0.113.5 port 51234"),
            Some(Seen::Failure { service: "ssh", ip: "203.0.113.5".into(), user: "admin".into() })
        );
        assert_eq!(parse_sshd("Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2"), None);
        assert_eq!(
            parse_sshd("Failed password for root from 2001:db8::7 port 4022 ssh2"),
            Some(Seen::Failure { service: "ssh", ip: "2001:db8::7".into(), user: "root".into() })
        );
        assert_eq!(
            parse_sshd("Accepted publickey for admin from 198.51.100.20 port 49790 ssh2: ED25519 SHA256:x"),
            Some(Seen::Success { service: "ssh", ip: "198.51.100.20".into(), user: "admin".into() })
        );
        assert_eq!(
            parse_sshd("pam_faillock(sshd:auth): Consecutive login failures for user bob account temporarily locked"),
            Some(Seen::Lockout { service: "ssh", user: "bob".into() })
        );
        assert_eq!(parse_sshd("Failed publickey for root from 203.0.113.5 port 1 ssh2: RSA SHA256:x"), None);
        assert_eq!(parse_sshd("Connection closed by 203.0.113.5 port 1 [preauth]"), None);
        assert_eq!(parse_sshd("Invalid user  from 203.0.113.5 port 1"), Some(Seen::Failure { service: "ssh", ip: "203.0.113.5".into(), user: "".into() }));
    }

    #[test]
    fn series_then_login_and_attackers() {
        let mut c = Counters::default();
        let t = 1_800_000_000;
        for i in 0..12 {
            c.add(Seen::Failure { service: "ssh", ip: "203.0.113.5".into(), user: format!("u{}", i % 3) }, t + i);
        }
        for i in 0..4 {
            c.add(Seen::Failure { service: "ssh", ip: "198.51.100.1".into(), user: "alex".into() }, t + i);
        }
        c.add(Seen::Success { service: "ssh", ip: "198.51.100.1".into(), user: "alex".into() }, t + 30);
        assert!(c.events.is_empty()); // 4 mistakes and a login — not a series
        let r = c.report("linux", t + 60, false);
        assert_eq!(r.attackers.len(), 1); // 12 within the hour; the one who logged in is never sent
        assert_eq!(r.windows[0].attempts, 16);
        assert_eq!(r.windows[0].ips, 2);
        c.add(Seen::Success { service: "ssh", ip: "203.0.113.5".into(), user: "u1".into() }, t + 100);
        assert_eq!(c.events.len(), 1);
        assert_eq!(c.events[0].failures, 12);
        c.add(Seen::Success { service: "ssh", ip: "203.0.113.5".into(), user: "u1".into() }, t + 110);
        assert_eq!(c.events.len(), 1); // a second login after the same series — no second alarm
        let r = c.report("linux", t + 120, true);
        assert!(r.attackers.is_empty()); // logged in now — not for the shared list
        let d = r.details.unwrap();
        assert_eq!(d.ips[0].users[0], ("u0".into(), 4));
        c.prune(t + KEEP + 3600);
        assert!(c.ips.is_empty() && c.windows.is_empty() && c.events.is_empty());
    }
}
