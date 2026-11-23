//! Windows inventory: system version, installed software (as «Programs and Features» shows it), services, listening
//! ports with the owning process, addresses, and the missing system updates (from Windows itself, see `updates`).
//! Never file contents, passwords, keys or traffic.

use super::sys;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetExtendedTcpTable,
    GetExtendedUdpTable, IP_ADAPTER_ADDRESSES_LH, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::core::{PCWSTR, PWSTR};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

pub const SCHEMA: u32 = 1;

#[derive(Serialize, Debug)]
pub struct Inventory {
    pub schema: u32,
    pub platform: &'static str,
    pub agent_version: String,
    pub collected_at: u64,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub os: OsInfo,
    pub software: Vec<Software>,
    pub services: Vec<Service>,
    pub ports: Vec<Port>,
    pub updates: super::updates::Updates,
    pub errors: Vec<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct OsInfo {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub product_name: String,
    pub edition: String,
    pub display_version: String,
    pub build: String,
    pub ubr: u32,
    pub installation_type: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Software {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub arch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub installed: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Service {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start: String,
    pub account: String,
    /// The program only, never the arguments (they may contain secrets).
    pub program: String,
    /// SHA-256 of the whole command line (program and arguments): tells that the arguments changed without sending
    /// them. Only for the compromise indicators, not in the inventory.
    #[serde(skip)]
    pub command_id: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Port {
    pub proto: String,
    pub address: String,
    pub port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub process: String,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn hostname() -> String {
    sys::hostname()
}

fn hklm(path: &str) -> std::io::Result<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
}

fn s(key: &RegKey, name: &str) -> String {
    key.get_value::<String, _>(name).map(|v| v.trim().to_string()).unwrap_or_default()
}

fn dw(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

pub mod os {
    use super::*;

    pub fn collect() -> OsInfo {
        let Ok(k) = hklm(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") else { return OsInfo::default() };
        let product_name = s(&k, "ProductName");
        let build = s(&k, "CurrentBuild");
        let ubr = dw(&k, "UBR").unwrap_or(0);
        let display_version = s(&k, "DisplayVersion");
        let major = dw(&k, "CurrentMajorVersionNumber").unwrap_or(10);
        let minor = dw(&k, "CurrentMinorVersionNumber").unwrap_or(0);
        let version_id = format!("{major}.{minor}.{build}.{ubr}");
        let mut pretty_name = product_name.clone();
        if !display_version.is_empty() {
            pretty_name.push_str(&format!(" {display_version}"));
        }
        pretty_name.push_str(&format!(" (build {build}.{ubr})"));
        OsInfo {
            id: "windows".into(),
            version_id,
            pretty_name,
            product_name,
            edition: s(&k, "EditionID"),
            display_version,
            build,
            ubr,
            installation_type: s(&k, "InstallationType"),
        }
    }
}

/// Installed software as «Programs and Features» lists it: entries with a name, not system components, not updates.
pub fn software(errors: &mut Vec<String>) -> Vec<Software> {
    let mut out = BTreeSet::new();
    let roots = [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "x64"),
        (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "x86"),
    ];
    for (path, arch) in roots {
        let root = match hklm(path) {
            Ok(r) => r,
            Err(e) => {
                if arch == "x64" {
                    errors.push(format!("software: {e}"));
                }
                continue;
            }
        };
        for name in root.enum_keys().flatten() {
            let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ | KEY_WOW64_64KEY) else { continue };
            let display = s(&k, "DisplayName");
            if display.is_empty() || dw(&k, "SystemComponent") == Some(1) || !s(&k, "ParentKeyName").is_empty() {
                continue;
            }
            let release = s(&k, "ReleaseType");
            if matches!(release.as_str(), "Update" | "Hotfix" | "Security Update" | "Service Pack") {
                continue;
            }
            out.insert(Software {
                name: display,
                version: s(&k, "DisplayVersion"),
                publisher: s(&k, "Publisher"),
                arch: arch.into(),
                installed: s(&k, "InstallDate"),
            });
        }
    }
    out.into_iter().collect()
}

/// A stamp of the installed software list: when it changes, the SYSTEM task sends a fresh inventory.
pub fn software_stamp() -> String {
    let list = software(&mut Vec::new());
    let text: String = list.iter().map(|s| format!("{}\t{}\t{}\n", s.name, s.version, s.arch)).collect();
    crate::win::updates::sha256_hex(text.as_bytes())
}

/// Program path from a service ImagePath, without arguments.
pub fn program_of(image_path: &str) -> String {
    let p = image_path.trim();
    let prog = if let Some(rest) = p.strip_prefix('"') {
        rest.split('"').next().unwrap_or_default().to_string()
    } else if let Some(i) = p.to_ascii_lowercase().find(".exe") {
        p[..i + 4].to_string()
    } else {
        p.split_whitespace().next().unwrap_or_default().to_string()
    };
    let lower = prog.to_ascii_lowercase();
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if lower.starts_with("%systemroot%") {
        format!("{root}{}", &prog[12..])
    } else if lower.starts_with(r"\systemroot") {
        format!("{root}{}", &prog[11..])
    } else if lower.starts_with(r"system32\") {
        format!(r"{root}\{prog}")
    } else if let Some(rest) = prog.strip_prefix(r"\??\") {
        rest.to_string()
    } else {
        prog
    }
}

/// Services (not drivers, not per-user instances whose names change at every logon) and the PID → names map.
pub fn services(errors: &mut Vec<String>) -> (Vec<Service>, HashMap<u32, Vec<String>>) {
    let mut out = Vec::new();
    let mut by_pid: HashMap<u32, Vec<String>> = HashMap::new();
    let reg = hklm(r"SYSTEM\CurrentControlSet\Services").ok();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else {
            errors.push("services: cannot open the service manager".into());
            return (out, by_pid);
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let r = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                if buf.is_empty() { None } else { Some(&mut buf) },
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            );
            let more = matches!(&r, Err(e) if WIN32_ERROR::from_error(e) == Some(ERROR_MORE_DATA));
            if r.is_err() && !more && !buf.is_empty() {
                errors.push(format!("services: {:?}", r.err()));
                break;
            }
            if buf.is_empty() || (more && count == 0) {
                buf = vec![0u8; needed as usize + 4096];
                resume = 0;
                continue;
            }
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                let st = it.ServiceStatusProcess;
                let kind = st.dwServiceType.0;
                if kind & 0x40 != 0 || kind & 0x80 != 0 {
                    continue; // SERVICE_USER_SERVICE / SERVICE_USERSERVICE_INSTANCE
                }
                let name = sys::from_pwstr(it.lpServiceName);
                let display_name = sys::from_pwstr(it.lpDisplayName);
                let state = match st.dwCurrentState.0 {
                    1 => "stopped",
                    2 => "starting",
                    3 => "stopping",
                    4 => "running",
                    5 => "continuing",
                    6 => "pausing",
                    7 => "paused",
                    _ => "unknown",
                };
                let (mut start, mut account, mut program, mut command_id) = (String::new(), String::new(), String::new(), String::new());
                if let Some(k) = reg.as_ref().and_then(|r| r.open_subkey_with_flags(&name, KEY_READ | KEY_WOW64_64KEY).ok()) {
                    start = match (dw(&k, "Start"), dw(&k, "DelayedAutostart")) {
                        (Some(2), Some(1)) => "auto-delayed",
                        (Some(2), _) => "auto",
                        (Some(3), _) => "manual",
                        (Some(4), _) => "disabled",
                        (Some(0), _) => "boot",
                        (Some(1), _) => "system",
                        _ => "",
                    }
                    .into();
                    account = s(&k, "ObjectName");
                    let image = s(&k, "ImagePath");
                    program = program_of(&image);
                    if !image.is_empty() {
                        command_id = super::updates::sha256_hex(image.as_bytes());
                    }
                }
                if st.dwProcessId != 0 {
                    by_pid.entry(st.dwProcessId).or_default().push(name.clone());
                }
                out.push(Service { name, display_name, state: state.into(), start, account, program, command_id });
            }
            if !more {
                break;
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out.sort();
    (out, by_pid)
}

fn process_name(pid: u32, services: &HashMap<u32, Vec<String>>) -> String {
    let base = match pid {
        0 => return String::new(),
        4 => "System".to_string(),
        _ => unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => {
                    let mut buf = vec![0u16; 1024];
                    let mut len = buf.len() as u32;
                    let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
                    let _ = CloseHandle(h);
                    if ok {
                        let full = String::from_utf16_lossy(&buf[..len as usize]);
                        full.rsplit('\\').next().unwrap_or_default().to_string()
                    } else {
                        String::new()
                    }
                }
                Err(_) => String::new(),
            }
        },
    };
    match services.get(&pid) {
        Some(names) if !base.is_empty() => {
            let mut n = names.clone();
            n.sort();
            format!("{base} ({})", n.join(", "))
        }
        _ => base,
    }
}

fn table<T>(get: impl Fn(Option<*mut core::ffi::c_void>, &mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    let _ = get(None, &mut size);
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize + std::mem::size_of::<T>() * 16];
        size = buf.len() as u32;
        let r = get(Some(buf.as_mut_ptr().cast()), &mut size);
        if r == NO_ERROR.0 {
            return Some(buf);
        }
        if r != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

/// Listening TCP sockets and bound UDP sockets, with the process (and its services) when it can be read: as SYSTEM
/// every process is readable, as the service account only some.
pub fn ports(services: &HashMap<u32, Vec<String>>) -> Vec<Port> {
    let mut out = BTreeSet::new();
    let mut add = |proto: &str, address: String, port: u16, pid: u32| {
        out.insert(Port { proto: proto.into(), address, port, user: String::new(), process: process_name(pid, services) });
    };
    unsafe {
        if let Some(b) = table::<MIB_TCPTABLE_OWNER_PID>(|p, n| GetExtendedTcpTable(p, n, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)) {
            let t = &*(b.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                add("tcp", Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(), u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
            }
        }
        if let Some(b) = table::<MIB_TCP6TABLE_OWNER_PID>(|p, n| GetExtendedTcpTable(p, n, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_LISTENER, 0)) {
            let t = &*(b.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                add("tcp6", Ipv6Addr::from(r.ucLocalAddr).to_string(), u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
            }
        }
        if let Some(b) = table::<MIB_UDPTABLE_OWNER_PID>(|p, n| GetExtendedUdpTable(p, n, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)) {
            let t = &*(b.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                add("udp", Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(), u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
            }
        }
        if let Some(b) = table::<MIB_UDP6TABLE_OWNER_PID>(|p, n| GetExtendedUdpTable(p, n, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)) {
            let t = &*(b.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                add("udp6", Ipv6Addr::from(r.ucLocalAddr).to_string(), u16::from_be(r.dwLocalPort as u16), r.dwOwningPid);
            }
        }
    }
    out.into_iter().collect()
}

/// Unicast addresses of the interfaces, without loopback, link-local and APIPA (for domain confirmation together
/// with the address the agent connects from, as on Linux).
pub fn addresses() -> Vec<String> {
    let mut out = BTreeSet::new();
    unsafe {
        let mut size = 16 * 1024u32;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        for _ in 0..3 {
            let mut buf = vec![0u8; size as usize];
            let r = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr().cast()), &mut size);
            if r == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if r != NO_ERROR.0 {
                break;
            }
            let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !a.is_null() {
                let mut u = (*a).FirstUnicastAddress;
                while !u.is_null() {
                    let sa = (*u).Address.lpSockaddr;
                    if !sa.is_null() {
                        if (*sa).sa_family == AF_INET {
                            let v4 = Ipv4Addr::from((*(sa as *const SOCKADDR_IN)).sin_addr.S_un.S_addr.to_ne_bytes());
                            if !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() {
                                out.insert(v4.to_string());
                            }
                        } else if (*sa).sa_family == AF_INET6 {
                            let v6 = Ipv6Addr::from((*(sa as *const SOCKADDR_IN6)).sin6_addr.u.Byte);
                            let first = v6.segments()[0];
                            if !v6.is_loopback() && (first & 0xffc0) != 0xfe80 && (first & 0xfe00) != 0xfc00 {
                                out.insert(v6.to_string());
                            }
                        }
                    }
                    u = (*u).Next;
                }
                a = (*a).Next;
            }
            break;
        }
    }
    out.into_iter().collect()
}

/// Full inventory, including the search for missing updates (seconds to minutes; run by the SYSTEM task).
pub fn collect() -> Inventory {
    let mut errors = Vec::new();
    let software = software(&mut errors);
    let (services, by_pid) = services(&mut errors);
    let ports = ports(&by_pid);
    let updates = super::updates::search();
    if let Some(e) = &updates.error {
        errors.push(format!("updates: {e}"));
    }
    Inventory {
        schema: SCHEMA,
        platform: "windows",
        agent_version: crate::VERSION.to_string(),
        collected_at: now(),
        hostname: hostname(),
        addresses: addresses(),
        os: os::collect(),
        software,
        services,
        ports,
        updates,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::program_of;

    #[test]
    fn service_program_without_arguments() {
        assert_eq!(program_of(r#""C:\Program Files\X\x.exe" --password secret"#), r"C:\Program Files\X\x.exe");
        assert_eq!(program_of(r"C:\Windows\system32\svchost.exe -k netsvcs -p"), r"C:\Windows\system32\svchost.exe");
        assert!(program_of(r"%SystemRoot%\System32\lsass.exe").ends_with(r"\System32\lsass.exe"));
        assert_eq!(program_of(r"\??\C:\drv\a.sys"), r"C:\drv\a.sys");
    }
}
