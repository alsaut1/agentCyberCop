//! Addresses assigned to this server's interfaces (from /proc): the control centre uses them only together with the
//! address the agent actually connects from, to confirm that a domain points to this server.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv6Addr;

/// IPv4 addresses marked "/32 host LOCAL" in /proc/net/fib_trie.
pub fn parse_fib_trie(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut last = "";
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|-- ") {
            last = rest;
        } else if t == "/32 host LOCAL" && !last.starts_with("127.") {
            out.insert(last.to_string());
        }
    }
    out
}

/// IPv6 addresses from /proc/net/if_inet6 (global scope only).
pub fn parse_if_inet6(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[0].len() != 32 || f[3] != "00" {
            continue; // scope 00 = global
        }
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = u8::from_str_radix(&f[0][i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        out.insert(Ipv6Addr::from(b).to_string());
    }
    out
}

pub fn collect() -> Vec<String> {
    let mut all = parse_fib_trie(&fs::read_to_string("/proc/net/fib_trie").unwrap_or_default());
    all.extend(parse_if_inet6(&fs::read_to_string("/proc/net/if_inet6").unwrap_or_default()));
    all.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_trie_locals() {
        let t = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 192.0.2.10\n        /32 host LOCAL\n     |-- 192.0.2.255\n        /32 link BROADCAST\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
        assert_eq!(parse_fib_trie(t).into_iter().collect::<Vec<_>>(), ["192.0.2.10"]);
    }

    #[test]
    fn inet6_global_only() {
        let t = "20010db8000000000000000000000001 02 40 00 80 eth0\nfe800000000000000000000000000001 02 40 20 80 eth0\n";
        assert_eq!(parse_if_inet6(t).into_iter().collect::<Vec<_>>(), ["2001:db8::1"]);
    }
}
