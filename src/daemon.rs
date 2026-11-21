//! The agent loop: heartbeat every 5 minutes, full inventory every 6 hours, right after packages change, or when the
//! client presses «Check now». If the control centre is unreachable the inventory waits on disk and goes later.

use crate::{client, inventory, state};
use std::time::Duration;

const TICK: u64 = 30;

struct Timers {
    last_heartbeat: u64,
    last_inventory: u64,
    db_stamp: u64,
    want_inventory: bool,
}

pub fn run() -> i32 {
    if state::is_revoked() {
        eprintln!("cybercop-agent: revoked in the control centre, nothing to do");
        return 0;
    }
    let (cfg, key) = match (state::config(), state::key()) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            eprintln!("cybercop-agent: not enrolled (run `cybercop-agent enroll <code>`)");
            return 1;
        }
    };
    let heartbeat_every = if cfg.heartbeat > 0 { cfg.heartbeat } else { 300 };
    let inventory_every = if cfg.inventory > 0 { cfg.inventory } else { 6 * 3600 };
    let mut t = Timers { last_heartbeat: 0, last_inventory: 0, db_stamp: 0, want_inventory: true };
    loop {
        let now = inventory::now();
        if now.saturating_sub(t.last_heartbeat) >= heartbeat_every {
            let body = serde_json::json!({"version": crate::VERSION}).to_string();
            match client::signed(&cfg.server, &cfg.agent_id, &key, "/agent-api/v1/heartbeat", body.as_bytes()) {
                Ok(answer) => {
                    t.last_heartbeat = now;
                    if answer["inventory_now"].as_bool() == Some(true) {
                        t.want_inventory = true;
                    }
                }
                Err(client::Error::Revoked) => return revoked(),
                Err(e) => eprintln!("cybercop-agent: heartbeat: {e}"),
            }
        }
        let stamp = inventory::packages::db_stamp();
        if stamp != t.db_stamp && t.db_stamp != 0 {
            t.want_inventory = true; // packages were installed or removed
        }
        if t.want_inventory || now.saturating_sub(t.last_inventory) >= inventory_every || state::take_pending("inventory").is_some() {
            let body = if t.want_inventory || state::take_pending("inventory").is_none() {
                let data = serde_json::to_vec(&inventory::collect()).expect("json");
                let _ = state::save_pending("inventory", &data);
                data
            } else {
                state::take_pending("inventory").unwrap_or_default()
            };
            match client::signed(&cfg.server, &cfg.agent_id, &key, "/agent-api/v1/inventory", &body) {
                Ok(_) => {
                    state::drop_pending("inventory");
                    t.last_inventory = now;
                    t.db_stamp = stamp;
                    t.want_inventory = false;
                }
                Err(client::Error::Revoked) => return revoked(),
                Err(e) => {
                    eprintln!("cybercop-agent: inventory kept for later: {e}");
                    t.want_inventory = false;
                    t.last_inventory = now.saturating_sub(inventory_every).saturating_add(TICK * 10); // retry in ~5 min
                }
            }
        }
        if t.db_stamp == 0 {
            t.db_stamp = stamp;
        }
        std::thread::sleep(Duration::from_secs(TICK));
    }
}

fn revoked() -> i32 {
    state::mark_revoked();
    state::drop_pending("inventory");
    eprintln!("cybercop-agent: the control centre revoked this agent; stopping");
    0
}
