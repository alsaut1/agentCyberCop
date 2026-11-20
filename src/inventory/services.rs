//! Running services from systemd (`systemctl list-units`). Without systemd the list is empty and an error is noted.

use serde::Serialize;
use std::process::Command;

#[derive(Serialize, Debug, PartialEq)]
pub struct Service {
    pub name: String,
}

pub fn parse(text: &str) -> Vec<Service> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| u.ends_with(".service"))
        .map(|u| Service { name: u.trim_end_matches(".service").to_string() })
        .collect()
}

pub fn collect(errors: &mut Vec<String>) -> Vec<Service> {
    let out = Command::new("systemctl")
        .args(["list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse(&String::from_utf8_lossy(&o.stdout)),
        _ => {
            errors.push("services: systemd not available".into());
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn units() {
        let s = super::parse("cron.service loaded active running Regular background program\nssh.service loaded active running OpenBSD\n");
        assert_eq!(s.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["cron", "ssh"]);
    }
}
