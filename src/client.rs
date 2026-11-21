//! Talking to the control centre: HTTPS only (a development build may also use plain HTTP to localhost),
//! every request after enrolment signed with the agent's own key.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

pub const PREFIX: &str = "cybercop-agent-v1";
static CLOCK_OFFSET: AtomicI64 = AtomicI64::new(0);

#[derive(Debug)]
pub enum Error {
    /// The control centre does not know this agent any more: stop sending.
    Revoked,
    Refused(u16, String),
    Network(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Revoked => write!(f, "the agent was revoked in the control centre"),
            Error::Refused(code, e) => write!(f, "refused ({code}): {e}"),
            Error::Network(e) => write!(f, "network: {e}"),
        }
    }
}

pub fn check_server(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if cfg!(feature = "dev") && (url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")) {
        return Ok(());
    }
    Err("the control centre address must start with https://".into())
}

pub fn message(method: &str, path: &str, ts: i64, nonce: &str, body: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(body);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}\n{method}\n{path}\n{ts}\n{nonce}\n{hex}").into_bytes()
}

fn now() -> i64 {
    crate::inventory::now() as i64 + CLOCK_OFFSET.load(Ordering::Relaxed)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .user_agent(&format!("cybercop-agent/{}", crate::VERSION))
        .build()
}

fn read(resp: Result<ureq::Response, ureq::Error>) -> Result<serde_json::Value, Error> {
    match resp {
        Ok(r) => r.into_json().map_err(|e| Error::Network(e.to_string())),
        Err(ureq::Error::Status(code, r)) => {
            let body: serde_json::Value = r.into_json().unwrap_or_default();
            let err = body["error"].as_str().unwrap_or_default().to_string();
            if code == 401 && err == "revoked" {
                return Err(Error::Revoked);
            }
            if code == 401 && err == "clock" {
                if let Some(t) = body["server_time"].as_i64() {
                    CLOCK_OFFSET.store(t - crate::inventory::now() as i64, Ordering::Relaxed);
                }
            }
            Err(Error::Refused(code, err))
        }
        Err(e) => Err(Error::Network(e.to_string())),
    }
}

pub fn enroll(server: &str, body: &serde_json::Value) -> Result<serde_json::Value, Error> {
    let url = format!("{}/agent-api/v1/enroll", server.trim_end_matches('/'));
    read(agent().post(&url).set("Content-Type", "application/json").send_string(&body.to_string()))
}

pub fn signed(server: &str, agent_id: &str, key: &SigningKey, path: &str, body: &[u8]) -> Result<serde_json::Value, Error> {
    let mut last = Error::Network("not sent".into());
    for _ in 0..2 {
        let ts = now();
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).map_err(|e| Error::Network(e.to_string()))?;
        let nonce: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let sig = key.sign(&message("POST", path, ts, &nonce, body));
        let url = format!("{}{}", server.trim_end_matches('/'), path);
        let resp = agent()
            .post(&url)
            .set("Content-Type", "application/json")
            .set("X-Agent", agent_id)
            .set("X-Time", &ts.to_string())
            .set("X-Nonce", &nonce)
            .set("X-Signature", &B64.encode(sig.to_bytes()))
            .send_bytes(body);
        match read(resp) {
            Err(Error::Refused(401, e)) if e == "clock" => last = Error::Refused(401, e), // retry with the corrected clock
            other => return other,
        }
    }
    Err(last)
}

pub fn public_key(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        let m = String::from_utf8(message("POST", "/agent-api/v1/heartbeat", 1700000000, "ab", b"{}")).unwrap();
        assert_eq!(m, "cybercop-agent-v1\nPOST\n/agent-api/v1/heartbeat\n1700000000\nab\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    }

    #[test]
    fn https_only_in_release() {
        assert!(check_server("https://agent.example").is_ok());
        assert!(check_server("ftp://x").is_err());
        assert_eq!(check_server("http://127.0.0.1:8000").is_ok(), cfg!(feature = "dev"));
    }
}
