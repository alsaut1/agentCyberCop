//! Linux: SSH log records since the last pass. From the systemd journal (sshd, and sshd-session in OpenSSH 9.8+),
//! remembering the journal cursor; without a journal — from /var/log/auth.log or /var/log/secure, remembering the
//! file and the offset. The first pass starts at the end: old records are not read.

use crate::auth::{self, Counters};
use crate::state;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::process::Command;

const STATE: &str = "auth-state.json";
const MAX_READ: u64 = 32 * 1024 * 1024; // per pass, from a file

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    inode: u64,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    pub counters: Counters,
}

pub fn load() -> State {
    fs::read(state::dir().join(STATE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save(s: &State) {
    if let Ok(b) = serde_json::to_vec(s) {
        let _ = state::write_private(&state::dir().join(STATE), &b);
    }
}

fn journal(s: &mut State, now: u64) -> bool {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--no-pager", "--quiet", "-o", "json"]);
    let first = s.cursor.is_empty();
    if first {
        cmd.args(["-n", "1"]); // first pass: only the current end of the journal (cursors are global positions)
    } else {
        cmd.arg(format!("--after-cursor={}", s.cursor)).args(["_COMM=sshd", "_COMM=sshd-session"]);
    }
    let Ok(out) = cmd.output() else { return false };
    if !out.status.success() {
        return false;
    }
    for line in out.stdout.split(|b| *b == b'\n') {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else { continue };
        if let Some(c) = v["__CURSOR"].as_str() {
            s.cursor = c.to_string();
        }
        if first {
            continue;
        }
        let at = v["__REALTIME_TIMESTAMP"].as_str().and_then(|t| t.parse::<u64>().ok()).map(|us| us / 1_000_000).unwrap_or(now);
        if let Some(msg) = v["MESSAGE"].as_str()
            && let Some(seen) = auth::parse_sshd(msg)
        {
            s.counters.add(seen, at);
        }
    }
    !s.cursor.is_empty()
}

/// Syslog line "Nov 22 12:00:01 host sshd[123]: MESSAGE" or "2026-11-22T12:00:01+00:00 host sshd[123]: MESSAGE".
fn syslog_message(line: &str) -> Option<&str> {
    let i = line.find("sshd")?;
    let rest = &line[i..];
    let j = rest.find("]: ").map(|j| j + 3).or_else(|| rest.find(": ").map(|j| j + 2))?;
    Some(&rest[j..])
}

fn file(s: &mut State, now: u64) {
    let Some(path) = ["/var/log/auth.log", "/var/log/secure"].into_iter().find(|p| fs::metadata(p).is_ok()) else { return };
    let Ok(meta) = fs::metadata(path) else { return };
    let first = s.file != path;
    if first || meta.ino() != s.inode || meta.len() < s.offset {
        // first pass, or the file was rotated: start at its end on the first pass, at its start after rotation
        s.offset = if first { meta.len() } else { 0 };
        s.file = path.into();
        s.inode = meta.ino();
        if first {
            return;
        }
    }
    let Ok(mut f) = fs::File::open(path) else { return };
    if f.seek(SeekFrom::Start(s.offset)).is_err() {
        return;
    }
    let mut buf = Vec::new();
    let _ = f.take(MAX_READ).read_to_end(&mut buf);
    let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0); // whole lines only
    for line in String::from_utf8_lossy(&buf[..end]).lines() {
        if let Some(msg) = syslog_message(line)
            && let Some(seen) = auth::parse_sshd(msg)
        {
            s.counters.add(seen, now); // the syslog time has no year/zone; the pass time is close enough
        }
    }
    s.offset += end as u64;
}

/// One pass: new records into the counters.
pub fn poll(s: &mut State, now: u64) {
    if !journal(s, now) {
        file(s, now);
    }
    s.counters.prune(now);
}

#[cfg(test)]
mod tests {
    #[test]
    fn syslog_lines() {
        assert_eq!(
            super::syslog_message("Nov 22 12:00:01 web sshd[123]: Invalid user a from 203.0.113.5 port 1"),
            Some("Invalid user a from 203.0.113.5 port 1")
        );
        assert_eq!(
            super::syslog_message("2026-11-22T12:00:01.1+00:00 web sshd-session[9]: Failed password for root from 203.0.113.5 port 1 ssh2"),
            Some("Failed password for root from 203.0.113.5 port 1 ssh2")
        );
    }
}
