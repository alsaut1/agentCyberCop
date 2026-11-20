//! Installed packages: dpkg status file (read directly) or the rpm database (through `rpm -qa`).
//! Only what the vulnerability engine needs: names, versions, architecture and the source package.

use serde::Serialize;
use std::fs;
use std::process::Command;

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_version: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub epoch: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub release: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_rpm: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub modularity: String,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Serialize, Debug, Default)]
pub struct Packages {
    pub format: String,
    pub items: Vec<Package>,
}

pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// dpkg status: blocks separated by empty lines; continuation lines start with a space.
pub fn parse_dpkg_status(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let (mut name, mut version, mut arch, mut status, mut source) =
            (String::new(), String::new(), String::new(), String::new(), String::new());
        for line in block.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim().to_string();
                match k {
                    "Package" => name = v,
                    "Version" => version = v,
                    "Architecture" => arch = v,
                    "Status" => status = v,
                    "Source" => source = v,
                    _ => {}
                }
            }
        }
        if name.is_empty() || status.split_whitespace().last() != Some("installed") {
            continue;
        }
        // "Source: openssl (3.5.7-1~deb13u3)" — the source version is given only when it differs.
        let (src, src_ver) = match source.split_once(' ') {
            Some((s, rest)) => (s.to_string(), rest.trim().trim_start_matches('(').trim_end_matches(')').to_string()),
            None if !source.is_empty() => (source.clone(), String::new()),
            None => (String::new(), String::new()),
        };
        out.push(Package { name, version, arch, source: src, source_version: src_ver, ..Default::default() });
    }
    out
}

/// One line per package from `rpm -qa --qf`: name, epoch, version, release, arch, source rpm, modularity label.
pub const RPM_QF: &str = "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\t%{MODULARITYLABEL}\\n";

pub fn parse_rpm_qa(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 6 || f[0] == "gpg-pubkey" {
            continue;
        }
        let clean = |s: &str| if s == "(none)" { String::new() } else { s.to_string() };
        out.push(Package {
            name: f[0].to_string(),
            epoch: f[1].parse().unwrap_or(0),
            version: f[2].to_string(),
            release: f[3].to_string(),
            arch: clean(f[4]),
            source_rpm: clean(f[5]),
            modularity: f.get(6).map(|s| clean(s)).unwrap_or_default(),
            ..Default::default()
        });
    }
    out
}

pub fn collect(errors: &mut Vec<String>) -> Packages {
    if let Ok(text) = fs::read_to_string(DPKG_STATUS) {
        return Packages { format: "deb".into(), items: parse_dpkg_status(&text) };
    }
    match Command::new("rpm").args(["-qa", "--qf", RPM_QF]).output() {
        Ok(o) if o.status.success() => {
            Packages { format: "rpm".into(), items: parse_rpm_qa(&String::from_utf8_lossy(&o.stdout)) }
        }
        Ok(o) => {
            errors.push(format!("rpm: exit {}", o.status));
            Packages::default()
        }
        Err(_) => {
            errors.push("packages: neither dpkg nor rpm found".into());
            Packages::default()
        }
    }
}

/// Modification time of the package database: the agent sends a fresh inventory when it changes.
pub fn db_stamp() -> u64 {
    let paths = [DPKG_STATUS, "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite"];
    paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok()?.modified().ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_installed_only_and_source() {
        let text = "Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl (3.5.7-1~deb13u3)\nVersion: 3.5.7-1~deb13u3\nDescription: x\n more\n\n\
Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n\n\
Package: adduser\nStatus: install ok installed\nArchitecture: all\nVersion: 3.152\n";
        let p = parse_dpkg_status(text);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].source.as_str(), p[0].source_version.as_str()), ("openssl", "3.5.7-1~deb13u3"));
        assert_eq!(p[1].source, "");
    }

    #[test]
    fn dpkg_source_without_version() {
        let p = parse_dpkg_status("Package: a\nStatus: install ok installed\nSource: b\nVersion: 1:2.0-3\n");
        assert_eq!((p[0].source.as_str(), p[0].source_version.as_str()), ("b", ""));
    }

    #[test]
    fn rpm_line() {
        let p = parse_rpm_qa("nginx\t1\t1.20.1\t14.module_el8\tx86_64\tnginx-1.20.1-14.module_el8.src.rpm\tnginx:1.20:8060020:abc\ngpg-pubkey\t0\ta\tb\t(none)\t(none)\t(none)\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].epoch, 1);
        assert_eq!(p[0].modularity, "nginx:1.20:8060020:abc");
    }
}
