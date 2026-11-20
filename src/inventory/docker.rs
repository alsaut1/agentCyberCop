//! Docker images through the local socket (GET /images/json). The agent reads it only if the server owner has
//! added the agent user to the docker group; otherwise the inventory says so.

use serde::Serialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[derive(Serialize, Debug, Default)]
pub struct Docker {
    pub available: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub state: String,
    pub images: Vec<Image>,
}

#[derive(Serialize, Debug)]
pub struct Image {
    pub id: String,
    pub tags: Vec<String>,
    pub created: i64,
}

const SOCKET: &str = "/var/run/docker.sock";

pub fn parse(body: &str) -> Vec<Image> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { return Vec::new() };
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|i| Image {
                    id: i["Id"].as_str().unwrap_or_default().to_string(),
                    tags: i["RepoTags"].as_array().map(|t| t.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                    created: i["Created"].as_i64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn collect() -> Docker {
    if !std::path::Path::new(SOCKET).exists() {
        return Docker { state: "not_installed".into(), ..Default::default() };
    }
    let mut s = match UnixStream::connect(SOCKET) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Docker { state: "no_access".into(), ..Default::default() },
        Err(_) => return Docker { state: "not_running".into(), ..Default::default() },
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    if s.write_all(b"GET /images/json HTTP/1.0\r\nHost: docker\r\n\r\n").is_err() {
        return Docker { state: "error".into(), ..Default::default() };
    }
    let mut buf = Vec::new();
    let _ = s.take(32 * 1024 * 1024).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    Docker { available: true, state: String::new(), images: parse(body) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn images() {
        let i = super::parse(r#"[{"Id":"sha256:ab","RepoTags":["nginx:1.27"],"Created":1700000000}]"#);
        assert_eq!(i[0].tags, ["nginx:1.27"]);
    }
}
