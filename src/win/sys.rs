//! Small Windows helpers: wide strings, who we run as, host name, time stamps.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid};
use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Null-terminated UTF-16 → String.
///
/// # Safety
/// `p` must be null or point to a null-terminated UTF-16 string.
pub unsafe fn from_pwstr(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string().unwrap_or_default() }
}

/// Running as LocalSystem (the scheduled task), not as the service account.
pub fn is_system() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut buf = vec![0u8; 256];
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut len).is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return false;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool()
    }
}

pub fn hostname() -> String {
    unsafe {
        let mut len = 0u32;
        let _ = GetComputerNameExW(ComputerNameDnsHostname, None, &mut len);
        let mut buf = vec![0u16; len as usize + 1];
        if GetComputerNameExW(ComputerNameDnsHostname, Some(PWSTR(buf.as_mut_ptr())), &mut len).is_ok() {
            return String::from_utf16_lossy(&buf[..len as usize]);
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// Unix seconds → "YYYY-MM-DD HH:MM:SSZ" (civil date from days, no time zone database needed).
pub fn utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn utc_now() -> String {
    utc(crate::win::inventory::now())
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_dates() {
        assert_eq!(super::utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(super::utc(1_795_300_000), "2026-11-21 22:26:40Z");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00:00Z");
    }
}
