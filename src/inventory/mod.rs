//! The inventory the agent sends: system, kernel, packages, services, listening ports, Docker images, site engines.
//! Never file contents, databases, passwords, keys or traffic.

pub mod docker;
pub mod os;
pub mod packages;
pub mod ports;
pub mod services;
pub mod webapps;

use serde::Serialize;

pub const SCHEMA: u32 = 1;

#[derive(Serialize, Debug)]
pub struct Inventory {
    pub schema: u32,
    pub agent_version: String,
    pub collected_at: u64,
    pub hostname: String,
    pub os: os::OsInfo,
    pub kernel: os::Kernel,
    pub packages: packages::Packages,
    pub services: Vec<services::Service>,
    pub ports: Vec<ports::Port>,
    pub docker: docker::Docker,
    pub webapps: Vec<webapps::WebApp>,
    pub errors: Vec<String>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn collect() -> Inventory {
    let mut errors = Vec::new();
    let packages = packages::collect(&mut errors);
    let services = services::collect(&mut errors);
    Inventory {
        schema: SCHEMA,
        agent_version: crate::VERSION.to_string(),
        collected_at: now(),
        hostname: hostname(),
        os: os::collect(),
        kernel: os::kernel(),
        packages,
        services,
        ports: ports::collect(),
        docker: docker::collect(),
        webapps: webapps::collect(),
        errors,
    }
}
