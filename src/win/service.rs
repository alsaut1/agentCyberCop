//! The Windows service `CybercopAgent` (account `NT SERVICE\CybercopAgent`, no privileges): heartbeat, takes an
//! offered update (download and check only), sends what the SYSTEM task left in `out\`. If the control centre is
//! unreachable the files simply wait and go later.

use crate::{client, daemon, state};
use crate::win::out_dir;
use std::ffi::OsString;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "CybercopAgent";

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> i32 {
    match service_dispatcher::start(NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cybercop-agent: `run` is started by the service manager ({e}); use `run-console` to try by hand");
            1
        }
    }
}

/// The same loop in the foreground, for a manual check (Ctrl+C to stop).
pub fn run_console() -> i32 {
    let (_tx, rx) = mpsc::channel();
    work(rx)
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let handler = move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(NAME, handler) else { return };
    let set = |state, accept| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN);
    let _ = work(rx);
    set(ServiceState::Stopped, ServiceControlAccept::empty());
}

fn mtime(name: &str) -> Option<SystemTime> {
    std::fs::metadata(out_dir().join(name)).ok()?.modified().ok()
}

fn work(stop: Receiver<()>) -> i32 {
    if state::is_revoked() {
        crate::log("revoked in the control centre, nothing to do");
        return 0;
    }
    let (cfg, key) = match (state::config(), state::key()) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            crate::log("not enrolled (run `cybercop-agent enroll <code>`)");
            return 1;
        }
    };
    crate::log(&format!("started, version {}", crate::VERSION));
    let heartbeat_every = if cfg.heartbeat > 0 { cfg.heartbeat } else { 300 };
    let (mut last_hb, mut retry_inv_at) = (0u64, 0u64);
    let (mut sent_ind, mut sent_inv): (Option<SystemTime>, Option<SystemTime>) = (None, None);
    loop {
        let now = crate::win::inventory::now();
        if now.saturating_sub(last_hb) >= heartbeat_every {
            match daemon::heartbeat(&cfg, &key) {
                Ok(inventory_now) => {
                    last_hb = now;
                    if inventory_now {
                        crate::win::request_inventory();
                    }
                }
                Err(client::Error::Revoked) => return daemon::revoked(),
                Err(e) => crate::log(&format!("heartbeat: {e}")),
            }
        }
        for (file, path, sent) in [("indicators.json", "/agent-api/v1/indicators", &mut sent_ind), ("inventory.json", "/agent-api/v1/inventory", &mut sent_inv)] {
            let m = mtime(file);
            if m.is_none() || m == *sent || (file == "inventory.json" && now < retry_inv_at) {
                continue;
            }
            let Ok(body) = std::fs::read(out_dir().join(file)) else { continue };
            match client::signed(&cfg.server, &cfg.agent_id, &key, path, &body) {
                Ok(_) => *sent = m,
                Err(client::Error::Revoked) => return daemon::revoked(),
                Err(e) => {
                    crate::log(&format!("{file} kept for later: {e}"));
                    if file == "inventory.json" {
                        retry_inv_at = now + 300;
                    }
                }
            }
        }
        match stop.recv_timeout(Duration::from_secs(daemon::TICK)) {
            Err(RecvTimeoutError::Timeout) => continue,
            _ => {
                crate::log("stopped");
                return 0;
            }
        }
    }
}

/// Called by the SYSTEM updater after the new version is in place: stop the service, wait, start it again.
pub fn restart() {
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return };
    let Ok(s) = m.open_service(NAME, ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::QUERY_STATUS) else { return };
    let _ = s.stop();
    for _ in 0..60 {
        if matches!(s.query_status().map(|x| x.current_state), Ok(ServiceState::Stopped)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if let Err(e) = s.start::<&str>(&[]) {
        crate::log(&format!("service did not start after the update: {e}"));
    }
}
