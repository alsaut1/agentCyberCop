//! Windows. The agent is split like on Linux, so that the part that talks to the network has no privileges:
//!
//! - the service `CybercopAgent` runs under its own unprivileged account (`NT SERVICE\CybercopAgent`): heartbeat,
//!   sends what the SYSTEM task has collected, downloads and checks an offered update;
//! - the scheduled task `CybercopAgent` runs `cybercop-agent system-tick` as SYSTEM every 5 minutes: installs a
//!   checked update, collects what needs privileges (Windows Update, owners of listening ports, all scheduled tasks)
//!   and writes the inventory and the break-in indicators to `out\` in the state folder. It never uses the network.

pub mod auth;
pub mod indicators;
pub mod inventory;
pub mod service;
pub mod sys;
pub mod tick;
pub mod updates;

use std::io::Write;
use std::path::PathBuf;

/// Written by the SYSTEM task, read by the service (the service account can only read here).
pub fn out_dir() -> PathBuf {
    crate::state::dir().join("out")
}

/// The service asks the SYSTEM task for a fresh inventory («Check now») by creating this file.
pub fn request_file() -> PathBuf {
    crate::state::dir().join("request-inventory")
}

pub fn request_inventory() {
    let _ = std::fs::write(request_file(), b"1");
}

/// The service asks the SYSTEM task for password guessing details (the client pressed the button).
pub fn auth_request_file() -> PathBuf {
    crate::state::dir().join("request-auth-details")
}

pub fn request_auth_details() {
    let _ = std::fs::write(auth_request_file(), b"1");
}

const LOG_MAX: u64 = 1024 * 1024;

/// `log\service.log` (agent service) or `log\system.log` (SYSTEM task); the previous ~1 MB is kept as `.old`.
pub fn log_file(msg: &str) {
    let name = if sys::is_system() { "system.log" } else { "service.log" };
    let dir = crate::state::dir().join("log");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(name);
    if std::fs::metadata(&path).map(|m| m.len() > LOG_MAX).unwrap_or(false) {
        let _ = std::fs::rename(&path, path.with_extension("log.old"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{} {msg}", sys::utc_now());
    }
}
