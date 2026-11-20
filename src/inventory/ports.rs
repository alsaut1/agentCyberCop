//! Listening sockets from /proc/net/{tcp,tcp6,udp,udp6}; the process name comes from /proc/<pid>/fd
//! (needs the read-only capabilities the service is started with; without them the process is left empty).

use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Port {
    pub proto: String,
    pub address: String,
    pub port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub process: String,
}

fn addr(hex: &str, v6: bool) -> Option<String> {
    if !v6 {
        let n = u32::from_str_radix(hex, 16).ok()?;
        return Some(Ipv4Addr::from(n.swap_bytes()).to_string());
    }
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?.swap_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

/// → (address, port, inode) of listening sockets in one /proc/net table.
pub fn parse_table(text: &str, v6: bool, udp: bool) -> Vec<(String, u16, u64)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let state = f[3];
        // TCP: 0A = LISTEN. UDP: 07 = unconnected (bound and waiting), remote is all zeros.
        let listening = if udp { state == "07" && f[2].trim_start_matches('0').starts_with(':') } else { state == "0A" };
        if !listening {
            continue;
        }
        let Some((a, p)) = f[1].split_once(':') else { continue };
        let (Some(address), Ok(port)) = (addr(a, v6), u16::from_str_radix(p, 16)) else { continue };
        out.push((address, port, f[9].parse().unwrap_or(0)));
    }
    out
}

fn socket_owners() -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else { return map };
    for entry in dir.flatten() {
        let pid = entry.file_name();
        let Some(pid) = pid.to_str().filter(|s| s.chars().all(|c| c.is_ascii_digit())) else { continue };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(i) = inode.parse() {
                        map.entry(i).or_insert_with(|| comm.clone());
                    }
                }
            }
        }
    }
    map
}

pub fn collect() -> Vec<Port> {
    let owners = socket_owners();
    let mut set = BTreeSet::new();
    for (file, proto, v6, udp) in [("tcp", "tcp", false, false), ("tcp6", "tcp", true, false), ("udp", "udp", false, true), ("udp6", "udp", true, true)] {
        let Ok(text) = fs::read_to_string(format!("/proc/net/{file}")) else { continue };
        for (address, port, inode) in parse_table(&text, v6, udp) {
            let process = owners.get(&inode).cloned().unwrap_or_default();
            set.insert(Port { proto: proto.into(), address, port, process });
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp4_listen_and_established() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n\
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n\
   2: 020000C0:0016 640033C6:D431 01 00000000:00000000 00:00000000 00000000     0        0 333 1\n";
        let p = parse_table(t, false, false);
        assert_eq!(p, vec![("0.0.0.0".into(), 22, 12345), ("127.0.0.1".into(), 8080, 222)]);
    }

    #[test]
    fn tcp6_any() {
        let t = "hdr\n   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9 1\n";
        assert_eq!(parse_table(t, true, false), vec![("::".into(), 80, 9)]);
    }
}
