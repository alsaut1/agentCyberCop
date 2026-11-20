//! cybercop-agent — the HT CYBERCOP server agent (Watcher). It only reads and reports; it changes nothing.

mod inventory;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> ! {
    eprintln!("usage: cybercop-agent <command>\n\n  inventory   print the inventory as JSON\n  version     print the version");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("inventory") => {
            let inv = inventory::collect();
            println!("{}", serde_json::to_string_pretty(&inv).expect("json"));
        }
        Some("version") => println!("cybercop-agent {VERSION}"),
        _ => usage(),
    }
}
