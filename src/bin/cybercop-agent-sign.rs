//! Release signing for the maintainer's laptop (offline). The secret key never leaves the laptop; the control centre
//! only receives the signature.
//!
//!   cybercop-agent-sign keygen KEYFILE          create a key (file readable only by you), print the public key
//!   cybercop-agent-sign public KEYFILE          print the public key again
//!   cybercop-agent-sign sign KEYFILE VERSION BINARY [ARCH]
//!                                               print the signature line for the release manifest

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::io::Write;

const PREFIX: &str = "cybercop-agent-release-v1";

fn die(msg: &str) -> ! {
    eprintln!("cybercop-agent-sign: {msg}");
    std::process::exit(1)
}

fn load(path: &str) -> SigningKey {
    let raw = std::fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let seed: [u8; 32] = raw.try_into().unwrap_or_else(|_| die("not a key file"));
    SigningKey::from_bytes(&seed)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") if a.len() == 3 => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| die(&e.to_string()));
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&a[2]).unwrap_or_else(|e| die(&format!("{}: {e}", a[2])));
            f.write_all(&seed).unwrap_or_else(|e| die(&e.to_string()));
            println!("{}", B64.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()));
        }
        Some("public") if a.len() == 3 => println!("{}", B64.encode(load(&a[2]).verifying_key().to_bytes())),
        Some("sign") if a.len() == 5 || a.len() == 6 => {
            let key = load(&a[2]);
            let data = std::fs::read(&a[4]).unwrap_or_else(|e| die(&format!("{}: {e}", a[4])));
            let sha: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
            let arch = a.get(5).map(String::as_str).unwrap_or("x86_64");
            let msg = format!("{PREFIX}\n{}\n{arch}\n{sha}", a[3]);
            let sig = B64.encode(key.sign(msg.as_bytes()).to_bytes());
            println!("{{\"version\": \"{}\", \"arch\": \"{arch}\", \"sha256\": \"{sha}\", \"signature\": \"{sig}\"}}", a[3]);
        }
        _ => die("usage: keygen KEYFILE | public KEYFILE | sign KEYFILE VERSION BINARY [ARCH]"),
    }
}
