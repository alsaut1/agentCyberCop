//! Linux: log records since the last pass.
//!
//! - The systemd journal (sshd and sshd-session, Postfix smtpd, Dovecot, Exim, vsftpd, ProFTPD, Pure-FTPd), remembering
//!   the journal cursor. Without a journal — the syslog files (auth.log or secure, mail.log or maillog, syslog or
//!   messages for the FTP servers), remembering each file and its offset.
//! - Always, when they exist: the logs the servers write themselves — Exim's main log, ProFTPD's SystemLog, vsftpd's
//!   log — and wtmp for ProFTPD's successful logins (ProFTPD does not log them by default).
//!
//! The first pass starts at the end: old records are not counted. Once, on the first start, the old logs that are on
//! the server (rotated and compressed ones too, up to 90 days) are read only for successful logins, to fill the known
//! networks (see `auth`). Nothing is read for a server that is not installed: its files do not exist, and the journal
//! filter does not match.

use crate::auth::{self, Counters, KNOWN_KEEP, Seen};
use crate::auth_parse;
use crate::state;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

const STATE: &str = "auth-state.json";
const MAX_READ: u64 = 32 * 1024 * 1024; // per pass and file
const WTMP: &str = "/var/log/wtmp";
const UTMP_SIZE: usize = 384; // struct utmp on Linux x86_64 and aarch64

/// The journal: one match group per process name, Dovecot by its syslog name (its log process is called «log»).
const JOURNAL_MATCH: &[&str] = &[
    "_COMM=sshd", "_COMM=sshd-session", "_COMM=smtpd", "_COMM=vsftpd", "_COMM=proftpd", "_COMM=pure-ftpd", "_COMM=exim4", "_COMM=exim",
    "+", "SYSLOG_IDENTIFIER=dovecot",
];

/// What a log file holds.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Exim,
    Proftpd,
    Vsftpd,
    /// syslog lines; `ftp_only` for syslog/messages (they repeat mail and, on some systems, SSH)
    Syslog { ftp_only: bool },
}

/// The servers' own logs: read in every pass when they exist.
const OWN: &[(&str, Kind)] = &[
    ("/var/log/exim4/mainlog", Kind::Exim),
    ("/var/log/exim/main.log", Kind::Exim),
    ("/var/log/proftpd/proftpd.log", Kind::Proftpd),
    ("/var/log/vsftpd.log", Kind::Vsftpd),
];

/// Syslog files, only without a journal: the first that exists in each group.
const SYSLOG: &[&[&str]] = &[&["/var/log/auth.log", "/var/log/secure"], &["/var/log/mail.log", "/var/log/maillog"], &["/var/log/syslog", "/var/log/messages"]];

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct Pos {
    inode: u64,
    offset: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default)]
    cursor: String,
    /// file → position (the servers' own logs, wtmp, and syslog files without a journal)
    #[serde(default)]
    files: BTreeMap<String, Pos>,
    /// vsftpd writes its own login lines (then its PAM lines are not counted, they would repeat them)
    #[serde(default)]
    vsftpd_own: bool,
    /// the old logs were read once for the known networks
    #[serde(default)]
    seeded: bool,
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

fn add(c: &mut Counters, seen: Option<(Seen, u32)>, at: u64) {
    if let Some((seen, n)) = seen {
        c.add_n(seen, at, n);
    }
}

/// A journal record → (program, message, time).
fn journal_record(v: &serde_json::Value) -> Option<(String, String, u64)> {
    let program = v["SYSLOG_IDENTIFIER"].as_str().or_else(|| v["_COMM"].as_str())?.to_string();
    let msg = match &v["MESSAGE"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(b) => String::from_utf8_lossy(&b.iter().filter_map(|x| x.as_u64().map(|x| x as u8)).collect::<Vec<u8>>()).into_owned(),
        _ => return None,
    };
    let at = v["__REALTIME_TIMESTAMP"].as_str().and_then(|t| t.parse::<u64>().ok()).map(|us| us / 1_000_000)?;
    Some((program, msg, at))
}

fn journal(s: &mut State, now: u64) -> bool {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--no-pager", "--quiet", "-o", "json"]);
    let first = s.cursor.is_empty();
    if first {
        cmd.args(["-n", "1"]); // first pass: only the current end of the journal (cursors are global positions)
    } else {
        cmd.arg(format!("--after-cursor={}", s.cursor)).args(JOURNAL_MATCH);
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
        let Some((program, msg, at)) = journal_record(&v) else { continue };
        if program == "vsftpd" && auth_parse::vsftpd_own(&msg).is_some() {
            s.vsftpd_own = true;
        }
        add(&mut s.counters, auth_parse::by_program(&program, &msg, s.vsftpd_own), at.min(now));
    }
    !s.cursor.is_empty()
}

/// Syslog line «Nov 22 12:00:01 host prog[123]: MESSAGE» or «2026-11-22T12:00:01+00:00 host prog[123]: MESSAGE» →
/// (program, message).
fn syslog_split(line: &str) -> Option<(&str, &str)> {
    let mut rest = line;
    let skip = if line.as_bytes().first()?.is_ascii_digit() { 1 } else { 3 }; // the time: 1 or 3 words
    for _ in 0..skip + 1 {
        rest = rest.trim_start().split_once(' ')?.1; // the time, then the host
    }
    let (tag, msg) = rest.split_once(": ")?;
    let program = tag.split('[').next()?;
    (!program.contains(' ')).then_some((program, msg))
}

fn ftp_program(p: &str) -> bool {
    matches!(p, "vsftpd" | "proftpd" | "pure-ftpd")
}

/// One line of a file of the given kind → what it says.
fn parse_line(kind: Kind, line: &str, vsftpd_own: bool) -> Option<(Seen, u32)> {
    match kind {
        Kind::Exim => auth_parse::exim(line),
        Kind::Proftpd => auth_parse::proftpd(line),
        Kind::Vsftpd => auth_parse::vsftpd_own(line),
        Kind::Syslog { ftp_only } => {
            let (program, msg) = syslog_split(line)?;
            if ftp_only != ftp_program(program) {
                return None;
            }
            auth_parse::by_program(program, msg, vsftpd_own)
        }
    }
}

/// New whole records of a file since the last pass (`unit` — 1 for text lines, the record size for wtmp). A file seen
/// on the agent's first pass starts at its end; one that appears later (a server installed after the agent) at its
/// start; after rotation (another inode, or shorter) at its start.
fn new_bytes(files: &mut BTreeMap<String, Pos>, path: &str, unit: usize, new_from_start: bool) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    let start = if new_from_start { 0 } else { meta.len() - meta.len() % unit as u64 };
    let pos = files.entry(path.into()).or_insert_with(|| Pos { inode: meta.ino(), offset: start });
    if meta.ino() != pos.inode || meta.len() < pos.offset {
        *pos = Pos { inode: meta.ino(), offset: 0 };
    }
    if meta.len() == pos.offset {
        return None;
    }
    let mut f = fs::File::open(path).ok()?;
    f.seek(SeekFrom::Start(pos.offset)).ok()?;
    let mut buf = Vec::new();
    let _ = f.take(MAX_READ).read_to_end(&mut buf);
    let end = if unit == 1 { buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0) } else { buf.len() - buf.len() % unit };
    buf.truncate(end);
    pos.offset += end as u64;
    Some(buf)
}

fn read_text(s: &mut State, path: &str, kind: Kind, now: u64) {
    let Some(buf) = new_bytes(&mut s.files, path, 1, s.seeded) else { return };
    for line in String::from_utf8_lossy(&buf).lines() {
        if kind == Kind::Vsftpd && auth_parse::vsftpd_own(line).is_some() {
            s.vsftpd_own = true;
        }
        // the time in these files has no zone (and syslog none of the year); the pass time is close enough
        add(&mut s.counters, parse_line(kind, line, s.vsftpd_own), now);
    }
}

/// wtmp records: (line, user, host, time). ProFTPD writes «ftpd<pid>» with the client address.
fn utmp_records(buf: &[u8]) -> impl Iterator<Item = (String, String, String, u64)> + '_ {
    buf.as_chunks::<UTMP_SIZE>().0.iter().map(|r| {
        let text = |a: usize, b: usize| String::from_utf8_lossy(r[a..b].split(|c| *c == 0).next().unwrap_or_default()).into_owned();
        let sec = u32::from_le_bytes([r[340], r[341], r[342], r[343]]) as u64;
        (text(8, 40), text(44, 76), text(76, 332), sec)
    })
}

fn ftp_login(line: &str, user: &str, host: &str) -> Option<Seen> {
    if !line.starts_with("ftpd") || user.is_empty() {
        return None;
    }
    Some(Seen::Success { service: "ftp", proto: "", ip: auth::address(host)?, user: user.chars().take(64).collect() })
}

fn wtmp(s: &mut State) {
    let Some(buf) = new_bytes(&mut s.files, WTMP, UTMP_SIZE, s.seeded) else { return };
    for (line, user, host, at) in utmp_records(&buf) {
        if let Some(seen) = ftp_login(&line, &user, &host) {
            s.counters.add(seen, at);
        }
    }
}

/// One pass: new records into the counters. The first pass of this version also reads the old logs once.
pub fn poll(s: &mut State, now: u64) {
    // the servers' own logs first: vsftpd's own lines decide whether its PAM lines in the journal are counted
    for (path, kind) in OWN {
        if Path::new(path).exists() {
            read_text(s, path, *kind, now);
        }
    }
    let have_journal = journal(s, now);
    if !have_journal {
        for group in SYSLOG {
            if let Some(path) = group.iter().find(|p| Path::new(p).exists()) {
                let ftp_only = group.contains(&"/var/log/messages");
                read_text(s, path, Kind::Syslog { ftp_only }, now);
            }
        }
    }
    wtmp(s);
    if !s.seeded {
        seed(&mut s.counters, now);
        s.seeded = true;
    }
    s.counters.prune(now);
}

// ---- once, on the first start: the old logs, only successful logins → known networks ----

/// The time at the start of a log line, if it has one: «2026-11-22T12:00:01», «2026-11-22 12:00:01» (Exim, ProFTPD),
/// «Nov 22 12:00:01» (syslog, the year guessed: not in the future), «Sat Nov 22 12:00:01 2026» (vsftpd). The zone
/// is taken as UTC: an error of hours does not matter for 90 days.
pub fn line_time(line: &str, now: u64) -> Option<u64> {
    let b = line.as_bytes();
    let num = |s: &str| s.parse::<i64>().ok();
    let hms = |t: &str| -> Option<(i64, i64, i64)> { Some((num(t.get(0..2)?)?, num(t.get(3..5)?)?, num(t.get(6..8)?)?)) };
    if b.len() >= 19 && b[4] == b'-' && b[7] == b'-' && (b[10] == b'T' || b[10] == b' ') {
        let (h, mi, s) = hms(&line[11..19])?;
        return auth::civil(num(&line[0..4])?, num(&line[5..7])?, num(&line[8..10])?, h, mi, s);
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let w: Vec<&str> = line.split_whitespace().take(5).collect();
    let month = |m: &str| MONTHS.iter().position(|x| *x == m).map(|i| i as i64 + 1);
    if w.len() >= 5 && w[4].len() == 4 && let (Some(mo), Some(y)) = (month(w[1]), num(w[4])) {
        let (h, mi, s) = hms(w[3])?;
        return auth::civil(y, mo, num(w[2])?, h, mi, s);
    }
    if w.len() >= 3 && let Some(mo) = month(w[0]) {
        let (h, mi, s) = hms(w[2])?;
        let year = 1970 + (now / 31_556_952) as i64;
        let t = auth::civil(year, mo, num(w[1])?, h, mi, s)?;
        return if t > now + 86_400 { auth::civil(year - 1, mo, num(w[1])?, h, mi, s) } else { Some(t) };
    }
    None
}

/// The old files of a log: «auth.log», «auth.log.1», «auth.log.2.gz», «secure-20261122», «maillog-20261115.gz».
fn rotated(path: &str) -> Vec<String> {
    let p = Path::new(path);
    let (Some(dir), Some(base)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else { return Vec::new() };
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n == base || n.strip_prefix(base).is_some_and(|r| r.starts_with('.') || r.starts_with('-')))
        .map(|n| dir.join(n).to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// A file as a stream of bytes, compressed ones through gzip.
fn open_any(path: &str) -> Option<Box<dyn Read>> {
    if path.ends_with(".gz") {
        let child = Command::new("gzip").args(["-dc", "--", path]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
        return Some(Box::new(child.stdout?));
    }
    if path.ends_with(".xz") || path.ends_with(".bz2") || path.ends_with(".zst") {
        return None;
    }
    Some(Box::new(fs::File::open(path).ok()?))
}

fn learn(c: &mut Counters, seen: Option<(Seen, u32)>, at: u64, now: u64) {
    if let Some((Seen::Success { service, ip, user, .. }, _)) = seen
        && at + KNOWN_KEEP >= now
    {
        c.learn(service, &user, &ip, at);
    }
}

fn seed_file(c: &mut Counters, path: &str, kind: Kind, now: u64) {
    let Some(r) = open_any(path) else { return };
    let mtime = fs::metadata(path).map(|m| m.mtime() as u64).unwrap_or(now);
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    while r.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
        let line = String::from_utf8_lossy(&buf);
        let seen = match kind {
            Kind::Syslog { .. } => syslog_split(&line).and_then(|(p, m)| auth_parse::by_program(p, m, true)),
            k => parse_line(k, &line, true),
        };
        if seen.is_some() {
            learn(c, seen, line_time(&line, now).unwrap_or(mtime), now);
        }
        buf.clear();
    }
}

fn seed_journal(c: &mut Counters, now: u64) {
    let since = format!("--since=@{}", now.saturating_sub(KNOWN_KEEP));
    let grep = "--grep=Accepted |Login: |Logged in: |sasl_username=|is now logged in|OK LOGIN| <= ";
    for with_grep in [true, false] {
        let mut cmd = Command::new("journalctl");
        cmd.args(["--no-pager", "--quiet", "-o", "json", &since]);
        if with_grep {
            cmd.arg(grep); // journalctl built without PCRE2 refuses --grep: then without it
        }
        let Ok(mut child) = cmd.args(JOURNAL_MATCH).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else { return };
        let mut lines = 0u64;
        if let Some(out) = child.stdout.take() {
            for line in BufReader::new(out).split(b'\n').map_while(Result::ok) {
                lines += 1;
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&line) else { continue };
                if let Some((program, msg, at)) = journal_record(&v) {
                    learn(c, auth_parse::by_program(&program, &msg, true), at, now);
                }
            }
        }
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        if ok || lines > 0 || !with_grep {
            return;
        }
    }
}

/// Read the old logs once: successful logins of the last 90 days → known networks. Failures are not counted.
pub fn seed(c: &mut Counters, now: u64) {
    seed_journal(c, now);
    let mut files: Vec<(String, Kind)> = Vec::new();
    for (path, kind) in OWN {
        files.extend(rotated(path).into_iter().map(|p| (p, *kind)));
    }
    for group in SYSLOG {
        for path in *group {
            files.extend(rotated(path).into_iter().map(|p| (p, Kind::Syslog { ftp_only: false })));
        }
    }
    for (path, kind) in files {
        seed_file(c, &path, kind, now);
    }
    for path in rotated(WTMP) {
        let Some(mut r) = open_any(&path) else { continue };
        let mut buf = Vec::new();
        if r.read_to_end(&mut buf).is_err() {
            continue;
        }
        for (line, user, host, at) in utmp_records(&buf) {
            if let Some(Seen::Success { service, ip, user, .. }) = ftp_login(&line, &user, &host)
                && at + KNOWN_KEEP >= now
            {
                c.learn(service, &user, &ip, at);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_lines() {
        assert_eq!(
            syslog_split("Nov 22 12:00:01 web sshd[123]: Invalid user a from 203.0.113.5 port 1"),
            Some(("sshd", "Invalid user a from 203.0.113.5 port 1"))
        );
        assert_eq!(
            syslog_split("2026-11-22T12:00:01.1+00:00 web sshd-session[9]: Failed password for root from 203.0.113.5 port 1 ssh2"),
            Some(("sshd-session", "Failed password for root from 203.0.113.5 port 1 ssh2"))
        );
        assert_eq!(
            syslog_split("Nov 22 20:58:01 mail postfix/submission/smtpd[2211]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x"),
            Some(("postfix/submission/smtpd", "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x"))
        );
        assert!(parse_line(Kind::Syslog { ftp_only: true }, "Nov 22 20:58:01 mail dovecot[1]: imap-login: Login: user=<a>, rip=198.51.100.20, lip=192.0.2.1", false).is_none());
        assert!(parse_line(Kind::Syslog { ftp_only: false }, "Nov 22 20:58:01 mail dovecot[1]: imap-login: Login: user=<a>, rip=198.51.100.20, lip=192.0.2.1", false).is_some());
        assert!(parse_line(Kind::Syslog { ftp_only: true }, "Nov 22 20:58:01 web pure-ftpd[7]: (?@203.0.113.5) [WARNING] Authentication failed for user [a]", false).is_some());
    }

    #[test]
    fn times() {
        let now = auth::civil(2026, 11, 22, 21, 0, 0).unwrap();
        assert_eq!(line_time("2026-11-22 21:00:56 dovecot_plain authenticator failed", now), auth::civil(2026, 11, 22, 21, 0, 56));
        assert_eq!(line_time("2026-11-22T21:00:56.123+01:00 web sshd[1]: x", now), auth::civil(2026, 11, 22, 21, 0, 56));
        assert_eq!(line_time("Sat Nov 22 21:02:41 2026 [pid 1234] [a] OK LOGIN", now), auth::civil(2026, 11, 22, 21, 2, 41));
        assert_eq!(line_time("Nov 22 20:58:01 web sshd[1]: x", now), auth::civil(2026, 11, 22, 20, 58, 1));
        assert_eq!(line_time("Dec 30 10:00:00 web sshd[1]: x", now), auth::civil(2025, 12, 30, 10, 0, 0)); // not in the future
        assert_eq!(line_time("garbage", now), None);
    }

    #[test]
    fn wtmp_record() {
        let mut r = vec![0u8; UTMP_SIZE];
        r[8..17].copy_from_slice(b"ftpd16324");
        r[44..48].copy_from_slice(b"jana");
        r[76..89].copy_from_slice(b"198.51.100.20");
        r[340..344].copy_from_slice(&1_795_381_362u32.to_le_bytes());
        let recs: Vec<_> = utmp_records(&r).collect();
        assert_eq!(recs[0], ("ftpd16324".into(), "jana".into(), "198.51.100.20".into(), 1_795_381_362));
        assert_eq!(ftp_login(&recs[0].0, &recs[0].1, &recs[0].2), Some(Seen::Success { service: "ftp", proto: "", ip: "198.51.100.20".into(), user: "jana".into() }));
        assert_eq!(ftp_login("pts/0", "jana", "198.51.100.20"), None);
        assert_eq!(ftp_login("ftpd1", "", "198.51.100.20"), None); // logout record
    }
}
