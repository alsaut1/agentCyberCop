//! `cybercop-agent system-tick`: the SYSTEM part, started by the scheduled task every 5 minutes (one instance at a
//! time). It installs a downloaded and checked update, then collects what needs privileges and leaves it in `out\`
//! for the agent service. It never talks to the network and never runs anything from the state folder.

use crate::state;
use crate::win::{inventory, out_dir, request_file};
use std::fs;
use std::path::Path;

fn age(path: &Path) -> Option<u64> {
    let m = fs::metadata(path).ok()?.modified().ok()?;
    Some(std::time::SystemTime::now().duration_since(m).map(|d| d.as_secs()).unwrap_or(0))
}

fn write(name: &str, data: &[u8]) -> std::io::Result<()> {
    state::write_private(&out_dir().join(name), data)
}

pub fn run() -> i32 {
    if !crate::win::sys::is_system() {
        eprintln!("cybercop-agent: system-tick runs as SYSTEM (from the scheduled task)");
        return 2;
    }
    let _ = fs::remove_file(Path::new(crate::update::BIN).with_extension("old"));
    if state::is_revoked() {
        return 0;
    }
    let Ok(cfg) = state::config() else { return 0 };
    if state::dir().join("update").join("ready").exists() {
        // Checked again here on SYSTEM's own copy; on success the service is restarted on the new version and the
        // next tick collects with it.
        return crate::update::apply_command();
    }
    let _ = fs::create_dir_all(out_dir());

    let ind = crate::win::indicators::collect();
    if let Err(e) = write("indicators.json", &serde_json::to_vec(&ind).expect("json")) {
        crate::log(&format!("indicators not written: {e}"));
    }

    // Password guessing: new log records since the last pass; the summary (and details when asked) for the service.
    let now = inventory::now();
    let mut auth = crate::win::auth::load();
    crate::win::auth::poll(&mut auth, now);
    crate::win::auth::save(&auth);
    let details = crate::win::auth_request_file().exists();
    let report = auth.counters.report("windows", now, details);
    match write("auth.json", &serde_json::to_vec(&report).expect("json")) {
        Ok(()) if details => {
            let _ = fs::remove_file(crate::win::auth_request_file());
        }
        Ok(()) => {}
        Err(e) => crate::log(&format!("auth summary not written: {e}")),
    }

    let every = if cfg.inventory > 0 { cfg.inventory } else { 6 * 3600 };
    let inv_path = out_dir().join("inventory.json");
    let stamp = inventory::software_stamp();
    let old_stamp = fs::read_to_string(out_dir().join("software.stamp")).unwrap_or_default();
    let requested = request_file().exists();
    let due = age(&inv_path).is_none_or(|a| a >= every) || requested || stamp != old_stamp;
    if due {
        let _ = fs::remove_file(request_file());
        let inv = inventory::collect();
        match write("inventory.json", &serde_json::to_vec(&inv).expect("json")) {
            Ok(()) => {
                let _ = write("software.stamp", stamp.as_bytes());
                crate::log(&format!(
                    "inventory collected: {} programs, {} services, {} ports, {} missing updates ({} s)",
                    inv.software.len(),
                    inv.services.len(),
                    inv.ports.len(),
                    inv.updates.items.len(),
                    inv.updates.seconds
                ));
            }
            Err(e) => crate::log(&format!("inventory not written: {e}")),
        }
    }
    0
}
