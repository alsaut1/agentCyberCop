//! Missing system updates, asked from Windows itself (the Windows Update Agent, the same engine as «Check for
//! updates»), the way the server is configured: through the organisation's WSUS server if a policy says so, otherwise
//! through Windows Update. Only the search runs; nothing is downloaded or installed. Needs SYSTEM.

use serde::Serialize;
use sha2::{Digest, Sha256};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::UpdateAgent::{IStringCollection, IUpdate2, IUpdateSearcher, IUpdateSession, UpdateSession};
use windows::core::{BSTR, Interface};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

pub const CRITERIA: &str = "IsInstalled=0 and IsHidden=0 and Type='Software'";

#[derive(Serialize, Debug, Default)]
pub struct Updates {
    /// "wsus" (the organisation's update server) or "windows_update".
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    pub searched_at: u64,
    pub seconds: u64,
    /// Updates were installed but take effect only after a restart (Windows keeps listing them as missing).
    pub reboot_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub items: Vec<Update>,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Update {
    pub id: String,
    pub kb: Vec<String>,
    pub title: String,
    /// Microsoft's rating: Critical, Important, Moderate, Low, or empty when Microsoft gives none.
    pub severity: String,
    pub cves: Vec<String>,
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub url: String,
    pub released: u64,
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// WSUS configured by policy → its address.
pub fn wsus_server() -> Option<String> {
    let k = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", KEY_READ | KEY_WOW64_64KEY)
        .ok()?;
    let server: String = k.get_value("WUServer").ok()?;
    let on: u32 = k.open_subkey_with_flags("AU", KEY_READ | KEY_WOW64_64KEY).ok()?.get_value("UseWUServer").ok()?;
    (on == 1 && !server.trim().is_empty()).then(|| server.trim().to_string())
}

fn strings(c: windows::core::Result<IStringCollection>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(c) = c {
        let n = unsafe { c.Count() }.unwrap_or(0);
        for i in 0..n {
            if let Ok(s) = unsafe { c.get_Item(i) } {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// OLE automation DATE (days since 1899-12-30) → Unix seconds.
fn ole_date(d: f64) -> u64 {
    if d <= 25569.0 { 0 } else { ((d - 25569.0) * 86400.0) as u64 }
}

fn query() -> windows::core::Result<Vec<Update>> {
    unsafe {
        let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)?;
        let _ = session.SetClientApplicationID(&BSTR::from("HT CYBERCOP agent"));
        let searcher: IUpdateSearcher = session.CreateUpdateSearcher()?;
        let result = searcher.Search(&BSTR::from(CRITERIA))?;
        let coll = result.Updates()?;
        let mut out = Vec::new();
        for i in 0..coll.Count()? {
            let u = coll.get_Item(i)?;
            let mut categories = Vec::new();
            if let Ok(cats) = u.Categories() {
                for j in 0..cats.Count().unwrap_or(0) {
                    if let Ok(c) = cats.get_Item(j)
                        && let Ok(n) = c.Name() {
                            categories.push(n.to_string());
                        }
                }
            }
            let kb: Vec<String> = strings(u.KBArticleIDs()).into_iter().map(|k| format!("KB{k}")).collect();
            out.push(Update {
                id: u.Identity().and_then(|x| x.UpdateID()).map(|b| b.to_string()).unwrap_or_default(),
                kb,
                title: u.Title().map(|b| b.to_string()).unwrap_or_default(),
                severity: u.MsrcSeverity().map(|b| b.to_string()).unwrap_or_default(),
                cves: u.cast::<IUpdate2>().map(|u2| strings(u2.CveIDs())).unwrap_or_default(),
                categories,
                url: u.SupportUrl().map(|b| b.to_string()).unwrap_or_default(),
                released: u.LastDeploymentChangeTime().map(ole_date).unwrap_or(0),
            });
        }
        Ok(out)
    }
}

pub fn search() -> Updates {
    let started = crate::win::inventory::now();
    let server = wsus_server();
    let mut up = Updates {
        source: if server.is_some() { "wsus".into() } else { "windows_update".into() },
        server: server.unwrap_or_default(),
        searched_at: started,
        ..Default::default()
    };
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED);
        match query() {
            Ok(items) => up.items = items,
            Err(e) => up.error = Some(format!("{:#010x} {}", e.code().0, e.message())),
        }
        if init.is_ok() {
            CoUninitialize();
        }
    }
    up.reboot_required = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", KEY_READ | KEY_WOW64_64KEY)
        .is_ok();
    up.items.sort_by(|a, b| a.kb.cmp(&b.kb).then(a.title.cmp(&b.title)));
    up.seconds = crate::win::inventory::now().saturating_sub(started);
    up
}

#[cfg(test)]
mod tests {
    #[test]
    fn ole_dates() {
        assert_eq!(super::ole_date(25569.0), 0);
        assert_eq!(super::ole_date(25570.5), 129_600);
    }
}
