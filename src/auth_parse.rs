//! Mail and FTP log lines → what they say, if anything we count. Only password checks over the network: one failed
//! check is one failure, a successful login is a success. PAM lines are not counted (each check of a mail or FTP server
//! is already in the server's own line), except vsftpd, which by default writes nothing of its own about logins.
//!
//! - Postfix (smtpd): «warning: NAME[ADDRESS]: SASL LOGIN authentication failed: …[, sasl_username=NAME]» and
//!   «…: client=NAME[ADDRESS], sasl_method=PLAIN, sasl_username=NAME»;
//! - Dovecot: «imap-login: Disconnected … (auth failed, N attempts in S secs): user=<NAME>, …, rip=ADDRESS, …» (2.3),
//!   «imap-login: Login aborted: … (auth failed, N attempts …) (auth_failed): user=<NAME>, …» (2.4), and the logins
//!   «imap-login: Login: user=<NAME>, …, rip=ADDRESS» (2.3) / «Logged in: …» (2.4); pop3-login and submission-login
//!   the same;
//! - Exim (its main log or syslog): «… authenticator failed for (HELO) [ADDRESS]:PORT: 535 … (set_id=NAME)» and a
//!   message accepted after a login «<= … H=(HELO) [ADDRESS]:PORT … A=AUTHENTICATOR:NAME …»;
//! - vsftpd: its own log «[pid N] [NAME] FAIL LOGIN: Client "ADDRESS"» / «OK LOGIN», or, without it, the PAM failure
//!   «pam_unix(vsftpd:auth): authentication failure; … ruser=NAME rhost=ADDRESS» (an address only when vsftpd does not
//!   look up host names);
//! - ProFTPD: «HOST (NAME[ADDRESS]): USER NAME (Login failed): …» and «USER NAME: no such user found from …»; its
//!   successful logins are not in its log by default — they are taken from wtmp (`auth_linux`);
//! - Pure-FTPd: «(?@ADDRESS) [WARNING] Authentication failed for user [NAME]» and «(?@ADDRESS) [INFO] NAME is now
//!   logged in».

use crate::auth::{Seen, address};

fn name(s: &str) -> String {
    s.trim().chars().take(64).collect()
}

/// Text between `start` and the first `end` after it.
fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let rest = &s[i..];
    Some(&rest[..rest.find(end).unwrap_or(rest.len())])
}

/// The last «[ADDRESS]» in a piece of text.
fn last_bracket(s: &str) -> Option<String> {
    let j = s.rfind(']')?;
    let i = s[..j].rfind('[')?;
    address(&s[i + 1..j])
}

/// Postfix smtpd (any syslog name ending in «smtpd»).
pub fn postfix(msg: &str) -> Option<(Seen, u32)> {
    if let Some(i) = msg.find(" authentication failed: ")
        && msg.starts_with("warning: ")
        && msg[..i].contains(": SASL ")
    {
        let reason = &msg[i..];
        if reason.contains("authentication server") {
            return None; // Postfix could not reach Dovecot: not a password check
        }
        let ip = last_bracket(&msg[..msg[..i].find(": SASL ")?])?;
        let user = between(reason, "sasl_username=", ",").map(name).unwrap_or_default();
        return Some((Seen::Failure { service: "mail", proto: "smtp", ip, user }, 1));
    }
    if msg.contains(": client=") && msg.contains("sasl_username=") {
        let client = between(msg, "client=", ",")?;
        let ip = last_bracket(client)?;
        let user = name(between(msg, "sasl_username=", ",")?);
        return Some((Seen::Success { service: "mail", proto: "smtp", ip, user }, 1));
    }
    None
}

/// Dovecot login processes (imap-login, pop3-login, submission-login).
pub fn dovecot(msg: &str) -> Option<(Seen, u32)> {
    let (process, rest) = msg.split_once("-login: ")?;
    let proto = match process.rsplit(' ').next()? {
        "imap" => "imap",
        "pop3" => "pop3",
        "submission" => "smtp",
        _ => return None,
    };
    let ip = address(between(rest, "rip=", ",")?)?;
    let user = between(rest, "user=<", ">").map(name).unwrap_or_default();
    if rest.starts_with("Login: ") || rest.starts_with("Logged in: ") {
        return Some((Seen::Success { service: "mail", proto, ip, user }, 1));
    }
    let n: u32 = between(rest, "(auth failed, ", " attempt")?.trim().parse().ok()?;
    Some((Seen::Failure { service: "mail", proto, ip, user }, n))
}

/// Exim, a main log line (with or without its date and time) or a syslog message.
pub fn exim(line: &str) -> Option<(Seen, u32)> {
    if let Some(i) = line.find(" authenticator failed for ") {
        let rest = &line[i + 26..];
        let head = &rest[..rest.find(": 5").or_else(|| rest.find(": 4")).unwrap_or(rest.len())];
        let ip = last_bracket(head)?;
        let user = between(rest, "(set_id=", ")").map(name).unwrap_or_default();
        return Some((Seen::Failure { service: "mail", proto: "smtp", ip, user }, 1));
    }
    if line.contains(" <= ") && line.contains(" A=") && line.contains(" H=") {
        let host = between(line, " H=", " P=").or_else(|| between(line, " H=", " A="))?;
        let ip = last_bracket(host)?;
        let auth = between(line, " A=", " ")?;
        let user = auth.split_once(':').map(|(_, u)| name(u)).unwrap_or_default();
        return Some((Seen::Success { service: "mail", proto: "smtp", ip, user }, 1));
    }
    None
}

/// vsftpd's own lines (its log, or syslog with `syslog_enable=YES`).
pub fn vsftpd_own(msg: &str) -> Option<(Seen, u32)> {
    let (ok, i) = if let Some(i) = msg.find("] OK LOGIN: Client \"") {
        (true, i)
    } else {
        (false, msg.find("] FAIL LOGIN: Client \"")?)
    };
    let user = name(&msg[msg[..i].rfind('[')? + 1..i]);
    let ip = address(between(&msg[i..], "Client \"", "\"")?)?;
    Some((if ok { Seen::Success { service: "ftp", proto: "", ip, user } } else { Seen::Failure { service: "ftp", proto: "", ip, user } }, 1))
}

/// vsftpd PAM failure (used only while vsftpd writes nothing of its own about logins).
pub fn vsftpd_pam(msg: &str) -> Option<(Seen, u32)> {
    if !msg.starts_with("pam_unix(vsftpd:auth): authentication failure;") {
        return None;
    }
    let ip = address(between(msg, " rhost=", " ")?)?; // a host name instead of an address: not usable
    let user = between(msg, " ruser=", " ").filter(|u| !u.is_empty()).or_else(|| between(msg, " user=", " ")).map(name).unwrap_or_default();
    Some((Seen::Failure { service: "ftp", proto: "", ip, user }, 1))
}

/// ProFTPD (its SystemLog or syslog).
pub fn proftpd(msg: &str) -> Option<(Seen, u32)> {
    let i = msg.find("USER ")?;
    let rest = &msg[i + 5..];
    let j = rest.find(" (Login failed)").or_else(|| rest.find(": no such user found"))?;
    let user = &rest[..j];
    // «HOST (NAME[ADDRESS]): USER» or «HOST (NAME[ADDRESS]) - USER»
    let ip = last_bracket(msg[..i].rsplit_once('(')?.1)?;
    Some((Seen::Failure { service: "ftp", proto: "", ip, user: name(user) }, 1))
}

/// Pure-FTPd (syslog).
pub fn pureftpd(msg: &str) -> Option<(Seen, u32)> {
    let ip = address(between(msg, "@", ")")?)?;
    if let Some(user) = between(msg, "[WARNING] Authentication failed for user [", "]") {
        return Some((Seen::Failure { service: "ftp", proto: "", ip, user: name(user) }, 1));
    }
    if !msg.contains(" is now logged in") {
        return None;
    }
    let user = between(msg, "[INFO] ", " is now logged in")?;
    Some((Seen::Success { service: "ftp", proto: "", ip, user: name(user) }, 1))
}

/// A syslog program name (journal SYSLOG_IDENTIFIER, or the tag in a syslog line) → the parser for its messages.
/// vsftpd PAM lines are passed separately (they need to know whether vsftpd writes its own lines).
pub fn by_program(program: &str, msg: &str, vsftpd_writes_own: bool) -> Option<(Seen, u32)> {
    match program {
        "sshd" | "sshd-session" => crate::auth::parse_sshd(msg).map(|s| (s, 1)),
        "dovecot" => dovecot(msg),
        "exim" | "exim4" => exim(msg),
        "proftpd" => proftpd(msg),
        "pure-ftpd" => pureftpd(msg),
        "vsftpd" => vsftpd_own(msg).or_else(|| if vsftpd_writes_own { None } else { vsftpd_pam(msg) }),
        p if p.starts_with("postfix") && p.ends_with("smtpd") => postfix(msg),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail(service: &'static str, proto: &'static str, ip: &str, user: &str, n: u32) -> Option<(Seen, u32)> {
        Some((Seen::Failure { service, proto, ip: ip.into(), user: user.into() }, n))
    }
    fn ok(service: &'static str, proto: &'static str, ip: &str, user: &str) -> Option<(Seen, u32)> {
        Some((Seen::Success { service, proto, ip: ip.into(), user: user.into() }, 1))
    }

    #[test]
    fn postfix_lines() {
        assert_eq!(
            postfix("warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=info"),
            fail("mail", "smtp", "203.0.113.5", "info", 1)
        );
        assert_eq!(
            postfix("warning: mx.example.net[2001:db8::5]: SASL PLAIN authentication failed: (reason unavailable)"),
            fail("mail", "smtp", "2001:db8::5", "", 1)
        );
        assert_eq!(postfix("warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: Connection lost to authentication server"), None);
        assert_eq!(
            postfix("A160110684DA: client=unknown[198.51.100.20], sasl_method=PLAIN, sasl_username=jana"),
            ok("mail", "smtp", "198.51.100.20", "jana")
        );
        assert_eq!(postfix("A160110684DA: client=unknown[198.51.100.20]"), None);
        assert_eq!(postfix("connect from unknown[203.0.113.5]"), None);
    }

    #[test]
    fn dovecot_lines() {
        assert_eq!(
            dovecot("imap-login: Disconnected: Connection closed (auth failed, 3 attempts in 15 secs): user=<jana>, method=PLAIN, rip=203.0.113.5, lip=192.0.2.1, TLS: Connection closed, session=<x>"),
            fail("mail", "imap", "203.0.113.5", "jana", 3)
        );
        assert_eq!(
            dovecot("pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 4 secs) (auth_failed): user=<info>, method=PLAIN, rip=::ffff:203.0.113.6, lip=192.0.2.1, TLS"),
            fail("mail", "pop3", "203.0.113.6", "info", 1)
        );
        assert_eq!(
            dovecot("imap-login: Login: user=<jana>, method=PLAIN, rip=198.51.100.20, lip=192.0.2.1, mpid=21738, TLS, session=<x>"),
            ok("mail", "imap", "198.51.100.20", "jana")
        );
        assert_eq!(
            dovecot("pop3-login: Logged in: user=<jana>, method=PLAIN, rip=198.51.100.20, lip=192.0.2.1, mpid=1, TLS"),
            ok("mail", "pop3", "198.51.100.20", "jana")
        );
        assert_eq!(dovecot("imap-login: Disconnected: Connection closed (no auth attempts in 0 secs): user=<>, rip=203.0.113.5, lip=192.0.2.1"), None);
        assert_eq!(dovecot("imap-login: Disconnected (tried to use disallowed plaintext auth): user=<>, rip=203.0.113.5, lip=192.0.2.1"), None);
        assert_eq!(dovecot("imap(jana)<1><x>: Disconnected: Logged out in=0 out=421"), None);
    }

    #[test]
    fn exim_lines() {
        assert_eq!(
            exim("2026-11-22 21:00:56 dovecot_plain_server authenticator failed for ([127.0.1.1]) [203.0.113.5]: 535 Incorrect authentication data (set_id=info)"),
            fail("mail", "smtp", "203.0.113.5", "info", 1)
        );
        assert_eq!(
            exim("2026-11-22 21:00:56 [1234] login authenticator failed for H=(User) [2001:db8::9]:51234: 535 Incorrect authentication data"),
            fail("mail", "smtp", "2001:db8::9", "", 1)
        );
        assert_eq!(
            exim("2026-11-22 21:01:13 1xVEgT-000000004DG-36xS <= jana@example.org H=([127.0.1.1]) [198.51.100.20]:40112 P=esmtpsa X=TLS1.3:x:256 CV=no A=dovecot_plain_server:jana S=401"),
            ok("mail", "smtp", "198.51.100.20", "jana")
        );
        assert_eq!(exim("2026-11-22 21:01:13 1xVEgT-000000004DG-36xS <= root@example.org U=root P=local S=401"), None);
    }

    #[test]
    fn ftp_lines() {
        assert_eq!(
            vsftpd_own("Sat Nov 22 21:02:41 2026 [pid 1234] [jana] FAIL LOGIN: Client \"::ffff:203.0.113.5\""),
            fail("ftp", "", "203.0.113.5", "jana", 1)
        );
        assert_eq!(vsftpd_own("[pid 1234] [jana] OK LOGIN: Client \"198.51.100.20\""), ok("ftp", "", "198.51.100.20", "jana"));
        assert_eq!(
            vsftpd_pam("pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=jana rhost=203.0.113.5  user=jana"),
            fail("ftp", "", "203.0.113.5", "jana", 1)
        );
        assert_eq!(vsftpd_pam("pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=jana rhost=host.example.net  user=jana"), None);
        assert_eq!(by_program("vsftpd", "pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=x rhost=203.0.113.5 ", true), None);
        assert_eq!(
            proftpd("2026-11-22 21:02:41,621 web proftpd[16318] 192.0.2.1 (203.0.113.5[203.0.113.5]): USER jana (Login failed): Incorrect password"),
            fail("ftp", "", "203.0.113.5", "jana", 1)
        );
        assert_eq!(
            proftpd("192.0.2.1 (203.0.113.5[203.0.113.5]) - USER admin: no such user found from 203.0.113.5 [203.0.113.5] to ::ffff:192.0.2.1:21"),
            fail("ftp", "", "203.0.113.5", "admin", 1)
        );
        assert_eq!(proftpd("192.0.2.1 (203.0.113.5[203.0.113.5]): FTP session opened."), None);
        assert_eq!(pureftpd("(?@203.0.113.5) [WARNING] Authentication failed for user [admin]"), fail("ftp", "", "203.0.113.5", "admin", 1));
        assert_eq!(pureftpd("(?@198.51.100.20) [INFO] jana is now logged in"), ok("ftp", "", "198.51.100.20", "jana"));
        assert_eq!(pureftpd("(?@203.0.113.5) [INFO] New connection from 203.0.113.5"), None);
    }

    #[test]
    fn programs() {
        assert!(by_program("postfix/submission/smtpd", "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x", false).is_some());
        assert!(by_program("postfix/qmgr", "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: x", false).is_none());
        assert!(by_program("auth", "pam_unix(dovecot:auth): authentication failure; ruser=x rhost=203.0.113.5", false).is_none());
    }
}
