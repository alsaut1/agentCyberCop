//! Windows password guessing, read by the SYSTEM task (the Security log needs it): only records after the last one
//! read, per log, by record number; the first pass starts at the end.
//!
//! - Security 4625 (failed logon) with a network address: logon type 10 is RDP; type 3 is RDP when the same address
//!   is in the RDP log (RdpCoreTS 140, «wrong user name or password») — with Network Level Authentication RDP
//!   failures look like any other network logon — otherwise «Windows network logon» (file shares and the like);
//! - Security 4624 (logon), types 10 and 3 with an address: a login after a series of failures;
//! - Security 4740: a locked account;
//! - OpenSSH/Operational: the same lines as sshd on Linux.

use crate::auth::{self, Counters, Seen};
use crate::state;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml,
};
use windows::core::PCWSTR;

const STATE: &str = "auth-state.json";
const MAX_EVENTS: usize = 50_000; // per log and pass
const SECURITY: &str = "Security";
const RDP: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
const SSH: &str = "OpenSSH/Operational";

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    /// log → last record number read
    #[serde(default)]
    last: BTreeMap<String, u64>,
    /// addresses from the RDP log in the last two hours (its record and the Security one may come in different passes)
    #[serde(default)]
    rdp_ips: BTreeMap<String, u64>,
    #[serde(default)]
    pub counters: Counters,
}

pub fn load() -> State {
    std::fs::read(state::dir().join(STATE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save(s: &State) {
    if let Ok(b) = serde_json::to_vec(s) {
        let _ = state::write_private(&state::dir().join(STATE), &b);
    }
}

fn render(h: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    unsafe {
        let _ = EvtRender(None, h, EvtRenderEventXml.0, 0, None, &mut used, &mut props);
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
        EvtRender(None, h, EvtRenderEventXml.0, (buf.len() * 2) as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut props).ok()?;
        let n = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]))
    }
}

/// Records of a log matching an XPath query, as XML, oldest first (or only the newest one).
fn query(log: &str, xpath: &str, newest_only: bool) -> Vec<String> {
    let mut out = Vec::new();
    let path = super::sys::wide(log);
    let q = super::sys::wide(xpath);
    let flags = EvtQueryChannelPath.0 | if newest_only { EvtQueryReverseDirection.0 } else { EvtQueryForwardDirection.0 };
    unsafe {
        let Ok(h) = EvtQuery(None, PCWSTR(path.as_ptr()), PCWSTR(q.as_ptr()), flags) else { return out };
        let mut batch = [0isize; 256];
        loop {
            let mut got = 0u32;
            if EvtNext(h, &mut batch, 0, 0, &mut got).is_err() || got == 0 {
                break;
            }
            for raw in &batch[..got as usize] {
                let e = EVT_HANDLE(*raw);
                if let Some(x) = render(e) {
                    out.push(x);
                }
                let _ = EvtClose(e);
            }
            if newest_only || out.len() >= MAX_EVENTS {
                break;
            }
        }
        let _ = EvtClose(h);
    }
    out
}

/// `<Name>value</Name>` inside the System part, or `<Data Name='Name'>value</Data>`.
pub fn field<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    for (open, close) in [(format!("<Data Name='{name}'>"), "</Data>"), (format!("<{name}>"), "")] {
        if let Some(i) = xml.find(&open) {
            let rest = &xml[i + open.len()..];
            let end = if close.is_empty() { rest.find(&format!("</{name}>"))? } else { rest.find(close)? };
            return Some(rest[..end].trim());
        }
    }
    None
}

/// `<TimeCreated SystemTime='2026-11-22T11:23:40.1234567Z'/>` → Unix seconds.
pub fn time(xml: &str) -> Option<u64> {
    let i = xml.find("SystemTime='")? + 12;
    let t = &xml[i..i + 19];
    let n = |a: usize, b: usize| t.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, s) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + s).ok()
}

/// "203.0.113.5:50744" or "[2001:db8::1]:50744" → the address.
pub fn strip_port(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default().to_string();
    }
    if s.matches(':').count() == 1 {
        return s.split(':').next().unwrap_or_default().to_string();
    }
    s.to_string()
}

fn record(xml: &str) -> u64 {
    field(xml, "EventRecordID").and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn remote(ip: &str) -> bool {
    !ip.is_empty() && ip != "-" && ip != "::1" && ip != "127.0.0.1" && ip.parse::<std::net::IpAddr>().is_ok()
}

/// New records of one log after the last one read (several queries: (System condition, extra condition)), or
/// only the position on the first pass.
fn new_records(s: &mut State, log: &str, queries: &[(&str, &str)]) -> Vec<String> {
    let Some(last) = s.last.get(log).copied() else {
        let newest = query(log, "*", true);
        s.last.insert(log.into(), newest.first().map(|x| record(x)).unwrap_or(0));
        return Vec::new();
    };
    let mut recs = Vec::new();
    for (sys, extra) in queries {
        recs.extend(query(log, &format!("*[System[EventRecordID>{last}{sys}]{extra}]"), false));
    }
    recs.sort_by_key(|x| record(x));
    if let Some(x) = recs.last() {
        s.last.insert(log.into(), record(x).max(last));
    }
    recs
}

/// The Security part: (failures with logon type and address, successes, lockouts) — classified after the RDP log.
pub fn poll(s: &mut State, now: u64) {
    // 131 — «accepted a TCP connection from client IP:port» (every RDP connection), 140 — «wrong user name or
    // password» from IP (not logged for every client).
    let rdp: Vec<String> = new_records(s, RDP, &[(" and (EventID=131 or EventID=140)", "")]);
    for x in &rdp {
        let ip = field(x, "IPString").map(String::from).or_else(|| field(x, "ClientIP").map(strip_port));
        if let Some(ip) = ip.filter(|ip| remote(ip)) {
            s.rdp_ips.insert(ip, time(x).unwrap_or(now));
        }
    }
    s.rdp_ips.retain(|_, t| *t + 2 * 3600 >= now);
    let rdp_ips: BTreeSet<String> = s.rdp_ips.keys().cloned().collect();
    let sec = new_records(
        s,
        SECURITY,
        &[
            (" and (EventID=4625 or EventID=4740)", ""),
            (" and EventID=4624", " and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']"),
        ],
    );
    for x in &sec {
        let id = field(x, "EventID").unwrap_or("");
        let at = time(x).unwrap_or(now);
        let user = field(x, "TargetUserName").unwrap_or("").chars().take(64).collect::<String>();
        match id {
            "4625" | "4624" => {
                let ip = field(x, "IpAddress").unwrap_or("");
                let ltype = field(x, "LogonType").unwrap_or("");
                if !remote(ip) || (ltype != "10" && ltype != "3") {
                    continue;
                }
                let service = if ltype == "10" || rdp_ips.contains(ip) { "rdp" } else { "windows_network" };
                let seen = if id == "4625" {
                    Seen::Failure { service, ip: ip.into(), user }
                } else {
                    Seen::Success { service, ip: ip.into(), user }
                };
                s.counters.add(seen, at);
            }
            "4740" => s.counters.add(Seen::Lockout { service: "windows", user }, at),
            _ => {}
        }
    }
    for x in new_records(s, SSH, &[("", "")]) {
        if let Some(msg) = field(&x, "payload")
            && let Some(seen) = auth::parse_sshd(msg)
        {
            s.counters.add(seen, time(&x).unwrap_or(now));
        }
    }
    s.counters.prune(now);
}

#[cfg(test)]
mod tests {
    #[test]
    fn fields_and_time() {
        let x = "<Event><System><EventID>4625</EventID><TimeCreated SystemTime='2026-11-22T11:23:40.1234567Z'/><EventRecordID>64975</EventRecordID></System><EventData><Data Name='TargetUserName'>ADMINISTRADOR</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>203.0.113.50</Data></EventData></Event>";
        assert_eq!(super::field(x, "EventID"), Some("4625"));
        assert_eq!(super::field(x, "IpAddress"), Some("203.0.113.50"));
        assert_eq!(super::record(x), 64975);
        assert_eq!(super::time(x), Some(1_795_346_620));
        assert_eq!(super::strip_port("198.51.100.20:50744"), "198.51.100.20");
        assert_eq!(super::strip_port("[2001:db8::1]:50744"), "2001:db8::1");
    }
}
