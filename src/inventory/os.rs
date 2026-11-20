//! Operating system and kernel: /etc/os-release, distribution release files, /proc/sys/kernel.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;

#[derive(Serialize, Default, Debug)]
pub struct OsInfo {
    pub id: String,
    pub id_like: String,
    pub version_id: String,
    pub pretty_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub debian_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub redhat_release: String,
}

#[derive(Serialize, Default, Debug)]
pub struct Kernel {
    pub release: String,
    pub version: String,
    pub arch: String,
}

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

fn read_trim(path: &str) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn collect() -> OsInfo {
    let text = fs::read_to_string("/etc/os-release")
        .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    let m = parse_os_release(&text);
    let get = |k: &str| m.get(k).cloned().unwrap_or_default();
    OsInfo {
        id: get("ID"),
        id_like: get("ID_LIKE"),
        version_id: get("VERSION_ID"),
        pretty_name: get("PRETTY_NAME"),
        debian_version: read_trim("/etc/debian_version"),
        redhat_release: read_trim("/etc/redhat-release"),
    }
}

pub fn kernel() -> Kernel {
    Kernel {
        release: read_trim("/proc/sys/kernel/osrelease"),
        version: read_trim("/proc/sys/kernel/version"),
        arch: std::env::consts::ARCH.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_quotes_and_comments() {
        let m = parse_os_release("# c\nID=debian\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID='13'\n");
        assert_eq!(m["ID"], "debian");
        assert_eq!(m["PRETTY_NAME"], "Debian GNU/Linux 13 (trixie)");
        assert_eq!(m["VERSION_ID"], "13");
    }
}
