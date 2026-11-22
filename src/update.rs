//! Self-update in two steps, so that the read-only agent never gets the right to replace itself
//! (Windows: the agent service runs under its own unprivileged account, step 2 is the SYSTEM task, see `win::tick`):
//!
//! 1. The agent (user cybercop-agent) downloads the new version offered by the control centre into its state
//!    directory, checks the SHA-256 and the signature, and writes `update/ready` with the version and signature.
//! 2. A small root service (`cybercop-agent apply-update`, started by a systemd path unit when `ready` appears) copies
//!    the file into a root-only directory, checks SHA-256, signature and version again on its own copy, replaces the
//!    binary atomically and restarts the agent. A wrong signature or an older version is refused and the agent stays
//!    on its current version.

use crate::release;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
pub const BIN: &str = "/usr/local/bin/cybercop-agent";
#[cfg(windows)]
pub const BIN: &str = r"C:\Program Files\CybercopAgent\cybercop-agent.exe";
/// Part of the signed message, so a signature for one platform's file never fits another's.
#[cfg(unix)]
pub const ARCH: &str = "x86_64";
#[cfg(windows)]
pub const ARCH: &str = "windows-x86_64";
const MAX_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(unix)]
const NOFOLLOW: u32 = 0o400000; // Linux O_NOFOLLOW: refuse to open a symbolic link
#[cfg(windows)]
const NOFOLLOW: u32 = 0x0020_0000; // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, not its target

/// Read a file the agent account controls without following links (the reader may be root or SYSTEM).
fn read_plain(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    let f = fs::OpenOptions::new().read(true).custom_flags(NOFOLLOW as i32).open(path);
    #[cfg(windows)]
    let f = fs::OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(path);
    let f = f.map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    let mut data = Vec::new();
    f.take(MAX_SIZE).read_to_end(&mut data).map_err(|e| e.to_string())?;
    Ok(data)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Offer {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

/// The agent file the installer put in place and its sha256: the control centre checks it against the signed
/// releases to tell the agent's own user, service and task from look-alikes.
#[derive(Serialize, Debug)]
pub struct AgentSelf {
    pub path: &'static str,
    pub sha256: String,
}

pub fn agent_self() -> AgentSelf {
    AgentSelf { path: BIN, sha256: fs::read(BIN).map(|d| hex(&d)).unwrap_or_default() }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(data)
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Everything an update must satisfy, checked twice: by the agent and again by the root updater on its own copy.
pub fn check(offer: &Offer, data: &[u8], current: &str) -> Result<&'static str, String> {
    if !release::newer(&offer.version, current) {
        return Err(format!("version {} is not newer than {current}", offer.version));
    }
    if hex(data) != offer.sha256.to_lowercase() {
        return Err("checksum mismatch".into());
    }
    release::verify(&offer.version, ARCH, &offer.sha256.to_lowercase(), &offer.signature)
}

fn update_dir() -> PathBuf {
    crate::state::dir().join("update")
}

/// Step 1 (agent user): download and check; on success leave the file and `ready` for the root updater.
pub fn fetch(offer: &Offer) -> Result<(), String> {
    if update_dir().join("ready").exists() {
        return Ok(()); // already waiting for the updater
    }
    crate::client::check_server(&offer.url)?;
    let resp = ureq::AgentBuilder::new().timeout(Duration::from_secs(300)).build().get(&offer.url).call()
        .map_err(|e| format!("download: {e}"))?;
    let mut data = Vec::new();
    resp.into_reader().take(MAX_SIZE).read_to_end(&mut data).map_err(|e| format!("download: {e}"))?;
    let key = check(offer, &data, crate::VERSION)?;
    let dir = update_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(dir.join("cybercop-agent.new"), &data).map_err(|e| e.to_string())?;
    fs::write(dir.join("ready"), serde_json::to_vec(offer).expect("json")).map_err(|e| e.to_string())?;
    crate::log(&format!("version {} downloaded, signed with the {key} key; waiting for the updater", offer.version));
    Ok(())
}

/// Step 2 (root): verify again on a private copy and install. Returns a message for the journal.
pub fn apply(state: &Path, bin: &Path, current: &str) -> Result<String, String> {
    let dir = state.join("update");
    let offer: Offer = serde_json::from_slice(&read_plain(&dir.join("ready"))?).map_err(|_| "ready: not a valid offer".to_string())?;
    let data = read_plain(&dir.join("cybercop-agent.new"))?;
    // From here on only the in-memory copy is used: the agent user cannot change it any more.
    let result = check(&offer, &data, current);
    let _ = fs::remove_file(dir.join("ready"));
    let _ = fs::remove_file(dir.join("cybercop-agent.new"));
    let key = result?;
    let tmp = bin.with_extension("new");
    fs::write(&tmp, &data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    // Windows: a running exe cannot be overwritten but can be renamed; the old file is removed on the next run.
    #[cfg(windows)]
    {
        let old = bin.with_extension("old");
        let _ = fs::remove_file(&old);
        if bin.exists() {
            fs::rename(bin, &old).map_err(|e| e.to_string())?;
        }
    }
    fs::rename(&tmp, bin).map_err(|e| e.to_string())?;
    Ok(format!("updated {current} -> {} (signed with the {key} key)", offer.version))
}

/// `cybercop-agent apply-update` run by the root updater service.
pub fn apply_command() -> i32 {
    let current = installed_version(Path::new(BIN)).unwrap_or_else(|| crate::VERSION.to_string());
    match apply(&crate::state::dir(), Path::new(BIN), &current) {
        Ok(msg) => {
            crate::log(&msg);
            restart_agent();
            0
        }
        Err(e) => {
            crate::log(&format!("update refused, staying on {current}: {e}"));
            1
        }
    }
}

#[cfg(unix)]
fn restart_agent() {
    let _ = std::process::Command::new("systemctl").args(["restart", "cybercop-agent"]).status();
}

#[cfg(windows)]
fn restart_agent() {
    crate::win::service::restart();
}

fn installed_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("version").output().ok()?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn offer(version: &str, data: &[u8], key: &SigningKey) -> Offer {
        let sha = hex(data);
        let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(&release::message(version, ARCH, &sha)).to_bytes());
        Offer { version: version.into(), url: "https://agent.example/x".into(), sha256: sha, signature: sig }
    }

    fn setup(name: &str, o: &Offer, data: &[u8]) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("cca-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("state/update")).unwrap();
        fs::write(base.join("state/update/ready"), serde_json::to_vec(o).unwrap()).unwrap();
        fs::write(base.join("state/update/cybercop-agent.new"), data).unwrap();
        fs::write(base.join("bin"), b"old").unwrap();
        (base.join("state"), base.join("bin"))
    }

    #[test]
    fn foreign_signature_refused_binary_untouched() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let o = offer("9.0.0", b"new-binary", &stranger);
        let (state, bin) = setup("foreign", &o, b"new-binary");
        assert!(apply(&state, &bin, "0.1.0").is_err());
        assert_eq!(fs::read(&bin).unwrap(), b"old");
        assert!(!state.join("update/ready").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn swapped_file_refused() {
        let k = SigningKey::from_bytes(&crate::release::tests::TEST_SECRET);
        let o = offer("9.0.0", b"signed-binary", &k);
        let (state, bin) = setup("swapped", &o, b"evil-binary");
        assert!(apply(&state, &bin, "0.1.0").unwrap_err().contains("checksum"));
        assert_eq!(fs::read(&bin).unwrap(), b"old");
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn test_key_works_only_in_dev_build() {
        let k = SigningKey::from_bytes(&crate::release::tests::TEST_SECRET);
        let o = offer("9.0.0", b"dev-binary", &k);
        let (state, bin) = setup("devkey", &o, b"dev-binary");
        let r = apply(&state, &bin, "0.1.0");
        if cfg!(feature = "dev") {
            assert!(r.is_ok(), "{r:?}");
            assert_eq!(fs::read(&bin).unwrap(), b"dev-binary");
        } else {
            assert!(r.is_err());
            assert_eq!(fs::read(&bin).unwrap(), b"old");
        }
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let k = SigningKey::from_bytes(&crate::release::tests::TEST_SECRET);
        let o = offer("9.0.0", b"x", &k);
        let (state, bin) = setup("symlink", &o, b"x");
        fs::remove_file(state.join("update/cybercop-agent.new")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", state.join("update/cybercop-agent.new")).unwrap();
        assert!(apply(&state, &bin, "0.1.0").is_err());
        assert_eq!(fs::read(&bin).unwrap(), b"old");
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn downgrade_refused() {
        let k = SigningKey::from_bytes(&crate::release::tests::TEST_SECRET);
        let o = offer("0.0.1", b"old-binary", &k);
        assert!(check(&o, b"old-binary", "0.1.0").unwrap_err().contains("not newer"));
    }
}
