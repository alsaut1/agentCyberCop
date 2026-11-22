//! Windows signs of a break-in: local users (and who is an administrator), scheduled tasks, services, listening
//! ports. The control centre takes the first report as the baseline and raises an alarm on anything new.
//!
//! Nothing secret leaves the server: no password data, scheduled tasks as name, program and a hash of the action —
//! never the full command line, which may contain passwords.

use super::inventory::{self, Port};
use super::sys;
use serde::Serialize;
use std::path::Path;
use windows::Win32::NetworkManagement::NetManagement::{
    FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_3, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetLocalGroupGetMembers,
    NetUserEnum, UF_ACCOUNTDISABLE, USER_INFO_1, USER_PRIV_ADMIN,
};
use windows::core::PCWSTR;

pub const SCHEMA: u32 = 1;

#[derive(Serialize, Debug)]
pub struct Indicators {
    pub schema: u32,
    pub platform: &'static str,
    pub collected_at: u64,
    pub agent: crate::update::AgentSelf,
    pub users: Vec<User>,
    pub tasks: Vec<Task>,
    pub services: Vec<ServiceEntry>,
    pub ports: Vec<Port>,
    pub errors: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct User {
    pub name: String,
    pub admin: bool,
    pub disabled: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Task {
    /// Full task path, e.g. `\Microsoft\Windows\Defrag\ScheduledDefrag`.
    pub name: String,
    pub user: String,
    pub enabled: bool,
    /// Program path as written in the task (no arguments), or `COM {class}`.
    pub program: String,
    /// Hash of all actions (program, arguments, COM handlers): changes when the task is changed.
    pub id: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceEntry {
    pub name: String,
    pub program: String,
    pub account: String,
    pub start: String,
}

fn administrators() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        // The group name is localised; S-1-5-32-544 resolves to it. "Administrators" works on English systems and
        // is the fallback.
        let group = sys::wide(&local_admin_group());
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total, mut resume) = (0u32, 0u32, 0usize);
        if NetLocalGroupGetMembers(PCWSTR::null(), PCWSTR(group.as_ptr()), 3, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, Some(&mut resume)) == 0 && !buf.is_null() {
            for m in std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_3, read as usize) {
                let full = sys::from_pwstr(m.lgrmi3_domainandname);
                out.push(full.rsplit('\\').next().unwrap_or_default().to_lowercase());
                out.push(full.to_lowercase());
            }
            let _ = NetApiBufferFree(Some(buf.cast()));
        }
    }
    out
}

fn local_admin_group() -> String {
    use windows::Win32::Security::{CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinAdministratorsSid};
    use windows::core::PWSTR;
    unsafe {
        let mut sid = vec![0u8; 68];
        let mut len = sid.len() as u32;
        if CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(windows::Win32::Security::PSID(sid.as_mut_ptr().cast())), &mut len).is_ok() {
            let mut name = vec![0u16; 256];
            let mut nlen = name.len() as u32;
            let mut dom = vec![0u16; 256];
            let mut dlen = dom.len() as u32;
            let mut use_ = SID_NAME_USE::default();
            if LookupAccountSidW(PCWSTR::null(), windows::Win32::Security::PSID(sid.as_mut_ptr().cast()), Some(PWSTR(name.as_mut_ptr())), &mut nlen, Some(PWSTR(dom.as_mut_ptr())), &mut dlen, &mut use_).is_ok() {
                return String::from_utf16_lossy(&name[..nlen as usize]);
            }
        }
    }
    "Administrators".into()
}

pub fn users(errors: &mut Vec<String>) -> Vec<User> {
    let admins = administrators();
    let host = sys::hostname().to_lowercase();
    let mut out = Vec::new();
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total, mut resume) = (0u32, 0u32, 0u32);
        let r = NetUserEnum(PCWSTR::null(), 1, FILTER_NORMAL_ACCOUNT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, Some(&mut resume));
        if r != 0 {
            errors.push(format!("users: NetUserEnum {r}"));
        }
        if !buf.is_null() {
            for u in std::slice::from_raw_parts(buf as *const USER_INFO_1, read as usize) {
                let name = sys::from_pwstr(u.usri1_name);
                let low = name.to_lowercase();
                let admin = u.usri1_priv == USER_PRIV_ADMIN || admins.contains(&low) || admins.contains(&format!("{host}\\{low}"));
                out.push(User { name, admin, disabled: u.usri1_flags.0 & UF_ACCOUNTDISABLE.0 != 0 });
            }
            let _ = NetApiBufferFree(Some(buf.cast()));
        }
    }
    out.sort();
    out
}

fn tag<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(after[..j].trim());
        rest = &after[j + close.len()..];
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// Task XML (as stored in System32\Tasks, UTF-16) → task entry.
pub fn parse_task(name: &str, xml: &str) -> Task {
    let actions = xml.find("<Actions").and_then(|i| xml[i..].find("</Actions>").map(|j| &xml[i..i + j])).unwrap_or("");
    let program = tag(actions, "Command")
        .first()
        .map(|c| unescape(c).trim().trim_matches('"').to_string())
        .or_else(|| tag(actions, "ClassId").first().map(|c| format!("COM {c}")))
        .unwrap_or_default();
    let user = tag(xml, "UserId").first().map(|u| unescape(u)).or_else(|| tag(xml, "GroupId").first().map(|g| unescape(g))).unwrap_or_default();
    let settings = xml.find("<Settings").and_then(|i| xml[i..].find("</Settings>").map(|j| &xml[i..i + j])).unwrap_or("");
    let enabled = tag(settings, "Enabled").first().map(|e| *e != "false").unwrap_or(true);
    Task { name: name.into(), user, enabled, program, id: super::updates::sha256_hex(actions.as_bytes()) }
}

fn read_utf16(path: &Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    if b.len() >= 2 && b[0] == 0xff && b[1] == 0xfe {
        let w: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Some(String::from_utf16_lossy(&w));
    }
    Some(String::from_utf8_lossy(b.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&b)).into_owned())
}

/// All scheduled tasks from `System32\Tasks` (complete only as SYSTEM).
pub fn tasks(errors: &mut Vec<String>) -> Vec<Task> {
    let root = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\Tasks");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            errors.push(format!("tasks: cannot read {}", dir.display()));
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(xml) = read_utf16(&p) {
                let rel = p.strip_prefix(&root).map(|r| r.display().to_string()).unwrap_or_default();
                out.push(parse_task(&format!("\\{rel}"), &xml));
            }
        }
    }
    out.sort();
    out
}

pub fn collect() -> Indicators {
    let mut errors = Vec::new();
    let users = users(&mut errors);
    let tasks = tasks(&mut errors);
    let (svcs, by_pid) = inventory::services(&mut errors);
    let services = svcs
        .into_iter()
        .map(|s| ServiceEntry { name: s.name, program: s.program, account: s.account, start: s.start })
        .collect();
    Indicators {
        schema: SCHEMA,
        platform: "windows",
        collected_at: inventory::now(),
        agent: crate::update::agent_self(),
        users,
        tasks,
        services,
        ports: inventory::ports(&by_pid),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_task;

    #[test]
    fn task_without_the_command_line() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?><Task><Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals><Settings><Enabled>false</Enabled></Settings><Actions Context="Author"><Exec><Command>"C:\Tools\backup.exe"</Command><Arguments>--password s3cret</Arguments></Exec></Actions></Task>"#;
        let t = parse_task(r"\Backup", xml);
        assert_eq!(t.program, r"C:\Tools\backup.exe");
        assert_eq!(t.user, "S-1-5-18");
        assert!(!t.enabled);
        assert!(!format!("{t:?}").contains("s3cret"));
        let changed = parse_task(r"\Backup", &xml.replace("s3cret", "other"));
        assert_ne!(t.id, changed.id);
    }

    #[test]
    fn com_handler_task() {
        let t = parse_task(r"\X", "<Task><Actions><ComHandler><ClassId>{ABC}</ClassId></ComHandler></Actions></Task>");
        assert_eq!(t.program, "COM {ABC}");
        assert!(t.enabled);
    }
}
