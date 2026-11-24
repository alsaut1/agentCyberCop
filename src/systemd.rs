//! systemd services for the break-in report (Linux).
//!
//! System services: every loaded service plus the enabled ones that are not loaded yet. Short-lived services made at
//! run time (`systemd-run`, `Transient=yes`) are skipped, and so are names that only appear as a dependency without an
//! installed file. Instances of a template (`getty@tty1`, `user@1000`) are reported once, under the template name
//! (`getty@.service`), with the command and user read from the template file itself — so a new login or a new terminal
//! does not look like a new or a changed service.
//!
//! Users' own services: unit files in `~/.config/systemd/user` of every home folder and in `/etc/systemd/user` (for
//! every user), with whether they are enabled. The agent reads these files itself.
//!
//! Nothing secret leaves the server: the program path and a hash of the whole command line only, never the arguments.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where system unit files live, in the order systemd reads them.
const UNIT_DIRS: [&str; 6] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator",
];
const MAX_USER_UNITS: usize = 200;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct Service {
    /// `sshd.service`; instances of a template under the template name, `getty@.service`.
    pub name: String,
    /// The unit file.
    pub file: String,
    /// `system` (installed by packages), `admin` (/etc, /usr/local, or an override file there), `runtime`,
    /// `generated` or `other`.
    pub origin: String,
    /// Program of the first command.
    pub program: String,
    /// SHA-256 of all start commands; for a template, of its own lines (with `%i`).
    pub id: String,
    /// `User=`; `root` when not set; `dynamic` with `DynamicUser=yes`.
    pub user: String,
    pub enabled: bool,
}

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct UserService {
    /// User of the home folder; empty for /etc/systemd/user (every user).
    pub owner: String,
    pub name: String,
    pub file: String,
    pub program: String,
    pub id: String,
    pub enabled: bool,
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn origin(path: &str) -> &'static str {
    if path.starts_with("/etc/") || path.starts_with("/usr/local/") {
        "admin"
    } else if path.starts_with("/run/systemd/generator") {
        "generated"
    } else if path.starts_with("/run/") {
        "runtime"
    } else if path.starts_with("/usr/") || path.starts_with("/lib/") {
        "system"
    } else {
        "other"
    }
}

/// `getty@tty1.service` → `getty@.service`; a name without `@` → None.
pub fn template_of(name: &str) -> Option<String> {
    let (left, right) = name.split_once('@')?;
    let suffix = right.rsplit_once('.').map(|(_, s)| s).unwrap_or("service");
    Some(format!("{left}@.{suffix}"))
}

/// Output of `systemctl show` for several units → one map per unit (keys may repeat: several ExecStart).
pub fn parse_show(text: &str) -> Vec<BTreeMap<String, Vec<String>>> {
    let mut out = Vec::new();
    let mut cur: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.entry(k.to_string()).or_default().push(v.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; start_time=… }` → (path, argv).
pub fn exec_of_show(v: &str) -> Option<(String, String)> {
    let path = v.split_once("path=")?.1.split(" ; ").next()?.trim().to_string();
    let argv = v.split_once("argv[]=").map(|(_, r)| r.split(" ; ignore_errors=").next().unwrap_or("").trim().to_string());
    Some((path, argv.unwrap_or_default()))
}

#[derive(Debug, Default, PartialEq)]
pub struct UnitFile {
    pub exec: Vec<String>,
    pub user: String,
    pub dynamic: bool,
}

/// What we need from a unit file: start commands, `User=`, `DynamicUser=` of the [Service] section.
pub fn parse_unit_file(text: &str) -> UnitFile {
    let mut u = UnitFile::default();
    let mut section = String::new();
    let mut joined = String::new();
    for raw in text.lines() {
        let l = raw.trim_end();
        if let Some(head) = l.strip_suffix('\\') {
            joined.push_str(head);
            joined.push(' ');
            continue;
        }
        joined.push_str(l);
        let line = std::mem::take(&mut joined);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section != "[Service]" {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "ExecStart" if v.is_empty() => u.exec.clear(),
            "ExecStart" => u.exec.push(v.to_string()),
            "User" => u.user = v.to_string(),
            "DynamicUser" => u.dynamic = matches!(v, "yes" | "true" | "1" | "on"),
            _ => {}
        }
    }
    u
}

/// First word of a command from a unit file, without systemd's prefixes (`-`, `@`, `:`, `+`, `!`).
pub fn program_of_line(cmd: &str) -> String {
    cmd.trim_start_matches(['-', '@', ':', '+', '!']).split_whitespace().next().unwrap_or("").to_string()
}

fn user_of(user: &str, dynamic: bool) -> String {
    if dynamic {
        "dynamic".into()
    } else if user.is_empty() {
        "root".into()
    } else {
        user.into()
    }
}

fn names(args: &[&str]) -> Vec<String> {
    let Ok(o) = Command::new("systemctl").args(args).output() else { return Vec::new() };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| n.ends_with(".service"))
        .map(String::from)
        .collect()
}

fn find_unit(name: &str) -> Option<PathBuf> {
    UNIT_DIRS.iter().map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}

fn from_template(name: &str, file: &Path, enabled: bool) -> Option<Service> {
    let text = fs::read_to_string(file).ok()?;
    let u = parse_unit_file(&text);
    let path = file.display().to_string();
    Some(Service {
        name: name.to_string(),
        origin: origin(&path).into(),
        file: path,
        program: u.exec.first().map(|c| program_of_line(c)).unwrap_or_default(),
        id: sha256_hex(u.exec.join("\n").as_bytes()),
        user: user_of(&u.user, u.dynamic),
        enabled,
    })
}

pub fn services() -> Vec<Service> {
    let loaded = names(&["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"]);
    let enabled: BTreeSet<String> = names(&[
        "list-unit-files", "--type=service", "--state=enabled,enabled-runtime", "--no-legend", "--no-pager",
    ])
    .into_iter()
    .collect();
    let mut ask: BTreeSet<String> = loaded.into_iter().collect();
    ask.extend(enabled.iter().filter(|n| !n.contains("@.")).cloned());
    let mut out: BTreeMap<String, Service> = BTreeMap::new();
    let mut templates: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    for n in enabled.iter().filter(|n| n.contains("@.")) {
        templates.insert(n.clone(), None);
    }
    if !ask.is_empty() {
        let mut cmd = Command::new("systemctl");
        cmd.args(["show", "--no-pager", "-p", "Id,LoadState,Transient,FragmentPath,DropInPaths,ExecStart,User,DynamicUser,UnitFileState", "--"]);
        cmd.args(&ask);
        if let Ok(o) = cmd.output() {
            for b in parse_show(&String::from_utf8_lossy(&o.stdout)) {
                let get = |k: &str| b.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
                let (id, fragment) = (get("Id"), get("FragmentPath"));
                if get("LoadState") != "loaded" || get("Transient") == "yes" || fragment.is_empty() {
                    continue;
                }
                if let Some(t) = template_of(&id) {
                    templates.insert(t, Some(PathBuf::from(fragment)));
                    continue;
                }
                let execs: Vec<(String, String)> = b.get("ExecStart").into_iter().flatten().filter_map(|v| exec_of_show(v)).collect();
                let lines: Vec<String> = execs.iter().map(|(p, a)| format!("{p}\t{a}")).collect();
                let drop_in_admin = get("DropInPaths").split_whitespace().any(|p| origin(p) == "admin");
                let state = get("UnitFileState");
                out.insert(id.clone(), Service {
                    origin: if drop_in_admin { "admin".into() } else { origin(&fragment).into() },
                    file: fragment,
                    program: execs.first().map(|(p, _)| p.clone()).unwrap_or_default(),
                    id: sha256_hex(lines.join("\n").as_bytes()),
                    user: user_of(&get("User"), get("DynamicUser") == "yes"),
                    enabled: state == "enabled" || state == "enabled-runtime" || enabled.contains(&id),
                    name: id,
                });
            }
        }
    }
    for (t, file) in templates {
        let file = file.or_else(|| find_unit(&t));
        if let Some(s) = file.and_then(|f| from_template(&t, &f, enabled.contains(&t))) {
            out.insert(t, s);
        }
    }
    out.into_values().collect()
}

/// Unit files of one user folder (`~/.config/systemd/user` or `/etc/systemd/user`): files there and links in
/// `*.wants` / `*.requires` (enabled).
pub fn user_dir(owner: &str, dir: &Path) -> Vec<UserService> {
    let Ok(rd) = fs::read_dir(dir) else { return Vec::new() };
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut on: BTreeSet<String> = BTreeSet::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let p = e.path();
        if p.is_dir() && (name.ends_with(".wants") || name.ends_with(".requires")) {
            for l in fs::read_dir(&p).into_iter().flatten().flatten() {
                let n = l.file_name().to_string_lossy().to_string();
                if !n.ends_with(".service") {
                    continue;
                }
                on.insert(n.clone());
                if !files.contains_key(&n) {
                    let target = fs::read_link(l.path()).map(|t| if t.is_absolute() { t } else { p.join(t) }).unwrap_or(l.path());
                    files.insert(n, target);
                }
            }
        } else if name.ends_with(".service") && p.is_file() {
            files.insert(name, p);
        }
        if files.len() > MAX_USER_UNITS {
            break;
        }
    }
    files
        .into_iter()
        .take(MAX_USER_UNITS)
        .filter_map(|(name, file)| {
            let text = fs::read_to_string(&file).ok()?;
            let u = parse_unit_file(&text);
            Some(UserService {
                owner: owner.to_string(),
                enabled: on.contains(&name),
                program: u.exec.first().map(|c| program_of_line(c)).unwrap_or_default(),
                id: sha256_hex(u.exec.join("\n").as_bytes()),
                file: file.display().to_string(),
                name,
            })
        })
        .collect()
}

/// Users' own services: every home folder from /etc/passwd (once per folder) and /etc/systemd/user.
pub fn user_services(homes: &[(String, String)]) -> Vec<UserService> {
    let mut out = user_dir("", Path::new("/etc/systemd/user"));
    let mut seen = BTreeSet::new();
    for (user, home) in homes {
        if home.is_empty() || home == "/" || !seen.insert(home.clone()) {
            continue;
        }
        out.extend(user_dir(user, &Path::new(home).join(".config/systemd/user")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_blocks_and_commands() {
        let text = "Id=ssh.service\nLoadState=loaded\nTransient=no\nFragmentPath=/usr/lib/systemd/system/ssh.service\n\
ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -o Password=secret ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n\
User=\n\nId=run-u7.service\nTransient=yes\n";
        let b = parse_show(text);
        assert_eq!(b.len(), 2);
        let (p, a) = exec_of_show(&b[0]["ExecStart"][0]).unwrap();
        assert_eq!((p.as_str(), a.as_str()), ("/usr/sbin/sshd", "/usr/sbin/sshd -D -o Password=secret"));
        assert_eq!(b[1]["Transient"][0], "yes");
    }

    #[test]
    fn templates_and_origins() {
        assert_eq!(template_of("getty@tty1.service").as_deref(), Some("getty@.service"));
        assert_eq!(template_of("user@1000.service").as_deref(), Some("user@.service"));
        assert_eq!(template_of("getty@.service").as_deref(), Some("getty@.service"));
        assert_eq!(template_of("sshd.service"), None);
        assert_eq!(origin("/usr/lib/systemd/system/a.service"), "system");
        assert_eq!(origin("/lib/systemd/system/a.service"), "system");
        assert_eq!(origin("/etc/systemd/system/a.service"), "admin");
        assert_eq!(origin("/usr/local/lib/systemd/system/a.service"), "admin");
        assert_eq!(origin("/run/systemd/generator/a.service"), "generated");
    }

    #[test]
    fn unit_file() {
        let u = parse_unit_file("[Unit]\nExecStart=/nope\n[Service]\nUser=%i\nExecStart=\nExecStart=-/usr/bin/agetty \\\n  -o '-p -- \\\\u' %I\n# x\nDynamicUser=no\n");
        assert_eq!(u.exec, vec!["-/usr/bin/agetty    -o '-p -- \\\\u' %I".to_string()]);
        assert_eq!((u.user.as_str(), u.dynamic), ("%i", false));
        assert_eq!(program_of_line(&u.exec[0]), "/usr/bin/agetty");
        assert_eq!(user_of("", false), "root");
        assert_eq!(user_of("www-data", true), "dynamic");
    }

    #[test]
    fn user_folder() {
        let dir = std::env::temp_dir().join(format!("cc-user-units-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("default.target.wants")).unwrap();
        fs::write(dir.join("sync.service"), "[Service]\nExecStart=/opt/sync/run --token abc\n").unwrap();
        fs::write(dir.join("idle.service"), "[Service]\nExecStart=%h/bin/idle\n").unwrap();
        std::os::unix::fs::symlink(dir.join("sync.service"), dir.join("default.target.wants/sync.service")).unwrap();
        let s = user_dir("someone", &dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(s.len(), 2);
        let sync = s.iter().find(|x| x.name == "sync.service").unwrap();
        assert!(sync.enabled && sync.program == "/opt/sync/run" && sync.owner == "someone");
        assert!(!s.iter().find(|x| x.name == "idle.service").unwrap().enabled);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("abc") && !json.contains("token"));
    }
}
