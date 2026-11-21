//! cybercop-agent — the HT CYBERCOP server agent (Watcher). It only reads and reports; it changes nothing.

mod client;
mod daemon;
#[cfg(unix)]
mod indicators;
#[cfg(unix)]
mod inventory;
mod release;
mod state;
mod update;
#[cfg(windows)]
mod win;
#[cfg(windows)]
use win::{indicators, inventory};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_SERVER: &str = "https://agent.cybercop.gtva.net";

/// A line for the service log. Linux: stderr, which systemd keeps in the journal. Windows: also a log file in the
/// state folder (`log\<process>.log`, the last ~1 MB), because a Windows service has no stderr.
pub fn log(msg: &str) {
    eprintln!("cybercop-agent: {msg}");
    #[cfg(windows)]
    win::log_file(msg);
}

fn usage() -> ! {
    eprintln!(
        "usage: cybercop-agent <command>\n\n  enroll [--server URL] CODE   register this server with a one-time code from the control centre\n  run                           work as a service\n  inventory                     print the inventory as JSON (nothing is sent)\n  indicators                    print the break-in indicators as JSON (nothing is sent)\n  version                       print the version"
    );
    std::process::exit(2)
}

fn enroll(args: &[String]) -> i32 {
    let mut server = DEFAULT_SERVER.to_string();
    let mut code = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--server" {
            server = it.next().cloned().unwrap_or_default();
        } else {
            code = Some(a.clone());
        }
    }
    let Some(code) = code else { usage() };
    if let Err(e) = client::check_server(&server) {
        eprintln!("cybercop-agent: {e}");
        return 2;
    }
    if state::config().is_ok() {
        eprintln!("cybercop-agent: already enrolled; remove {} to enrol again", state::dir().display());
        return 1;
    }
    let key = match state::new_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("cybercop-agent: cannot write the key to {}: {e}", state::dir().display());
            return 1;
        }
    };
    let os = inventory::os::collect();
    let body = serde_json::json!({
        "code": code, "public_key": client::public_key(&key), "hostname": inventory::hostname(),
        "os": os.pretty_name, "agent_version": VERSION,
    });
    match client::enroll(&server, &body) {
        Ok(answer) => {
            let cfg = state::Config {
                server,
                agent_id: answer["agent_id"].as_str().unwrap_or_default().to_string(),
                heartbeat: answer["intervals"]["heartbeat"].as_u64().unwrap_or(300),
                indicators: answer["intervals"]["indicators"].as_u64().unwrap_or(900),
                inventory: answer["intervals"]["inventory"].as_u64().unwrap_or(21600),
            };
            if let Err(e) = state::save_config(&cfg) {
                eprintln!("cybercop-agent: cannot save the configuration: {e}");
                return 1;
            }
            println!("cybercop-agent: enrolled");
            0
        }
        Err(e) => {
            let _ = std::fs::remove_file(state::dir().join("key"));
            eprintln!("cybercop-agent: enrolment failed: {e}");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("enroll") => enroll(&args[2..]),
        #[cfg(unix)]
        Some("run") => daemon::run(),
        #[cfg(windows)]
        Some("run") => win::service::run(),
        #[cfg(windows)]
        Some("run-console") => win::service::run_console(),
        #[cfg(windows)]
        Some("system-tick") => win::tick::run(),
        Some("apply-update") => update::apply_command(),
        Some("indicators") => {
            println!("{}", serde_json::to_string_pretty(&indicators::collect()).expect("json"));
            0
        }
        Some("inventory") => {
            println!("{}", serde_json::to_string_pretty(&inventory::collect()).expect("json"));
            0
        }
        Some("version") => {
            println!("cybercop-agent {VERSION}");
            0
        }
        _ => usage(),
    };
    std::process::exit(code);
}
