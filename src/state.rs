//! Agent state on disk: its own Ed25519 key (readable only by the agent user) and the enrolment answer.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub fn dir() -> PathBuf {
    std::env::var_os("CYBERCOP_AGENT_STATE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/var/lib/cybercop-agent"))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub server: String,
    pub agent_id: String,
    #[serde(default)]
    pub heartbeat: u64,
    #[serde(default)]
    pub indicators: u64,
    #[serde(default)]
    pub inventory: u64,
}

fn write_private(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)
}

pub fn new_key() -> std::io::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
    let key = SigningKey::from_bytes(&seed);
    fs::create_dir_all(dir())?;
    write_private(&dir().join("key"), &seed)?;
    Ok(key)
}

pub fn key() -> std::io::Result<SigningKey> {
    let seed = fs::read(dir().join("key"))?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| std::io::Error::other("bad key file"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn save_config(c: &Config) -> std::io::Result<()> {
    write_private(&dir().join("agent.json"), &serde_json::to_vec_pretty(c).expect("json"))
}

pub fn config() -> std::io::Result<Config> {
    let data = fs::read(dir().join("agent.json"))?;
    serde_json::from_slice(&data).map_err(|e| std::io::Error::other(e.to_string()))
}

pub fn save_pending(name: &str, data: &[u8]) -> std::io::Result<()> {
    write_private(&dir().join(format!("pending-{name}.json")), data)
}

pub fn take_pending(name: &str) -> Option<Vec<u8>> {
    fs::read(dir().join(format!("pending-{name}.json"))).ok()
}

pub fn drop_pending(name: &str) {
    let _ = fs::remove_file(dir().join(format!("pending-{name}.json")));
}

pub fn mark_revoked() {
    let _ = write_private(&dir().join("revoked"), b"revoked by the control centre\n");
}

pub fn is_revoked() -> bool {
    dir().join("revoked").exists()
}
