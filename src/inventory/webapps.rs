//! Site engines with their versions: WordPress (with plugins), Joomla, Drupal. Only version strings are read —
//! from the files where each engine declares its version — never site content or configuration.

use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Serialize, Debug)]
pub struct WebApp {
    pub kind: String,
    pub path: String,
    pub version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<Plugin>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct Plugin {
    pub name: String,
    pub version: String,
}

const ROOTS: [&str; 3] = ["/var/www", "/srv", "/home"];
const MAX_DEPTH: usize = 5;
const MAX_DIRS: usize = 20000;

fn head(path: &Path, limit: u64) -> String {
    let mut s = String::new();
    if let Ok(f) = fs::File::open(path) {
        let _ = f.take(limit).read_to_string(&mut s);
    }
    s
}

/// `$wp_version = '6.4.2';` and similar PHP assignments / constants.
pub fn php_value(text: &str, marker: &str) -> Option<String> {
    let i = text.find(marker)?;
    let rest = &text[i + marker.len()..];
    let q = rest.find(['\'', '"'])?;
    let quote = rest.as_bytes()[q] as char;
    let rest = &rest[q + 1..];
    let end = rest.find(quote)?;
    let v = &rest[..end];
    (!v.is_empty() && v.len() < 40).then(|| v.to_string())
}

pub fn plugin_header(text: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in text.lines().take(60) {
        let l = line.trim_start_matches(['*', ' ', '/', '\t']);
        if let Some(v) = l.strip_prefix("Plugin Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    Some((name?, version.unwrap_or_default()))
}

fn wp_plugins(root: &Path) -> Vec<Plugin> {
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(root.join("wp-content/plugins")) else { return out };
    for d in dirs.flatten().take(500) {
        let dir = d.path();
        if !dir.is_dir() {
            continue;
        }
        let slug = d.file_name().to_string_lossy().to_string();
        let mut files: Vec<PathBuf> = vec![dir.join(format!("{slug}.php"))];
        if let Ok(rd) = fs::read_dir(&dir) {
            files.extend(rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "php")).take(30));
        }
        if let Some((_, version)) = files.iter().filter(|p| p.is_file()).find_map(|p| plugin_header(&head(p, 8192))) {
            out.push(Plugin { name: slug, version });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn detect(dir: &Path) -> Option<WebApp> {
    let path = dir.to_string_lossy().to_string();
    let wp = dir.join("wp-includes/version.php");
    if wp.is_file() {
        let version = php_value(&head(&wp, 16384), "$wp_version")?;
        return Some(WebApp { kind: "wordpress".into(), path, version, plugins: wp_plugins(dir) });
    }
    let joomla = dir.join("libraries/src/Version.php");
    if joomla.is_file() {
        let t = head(&joomla, 16384);
        let major = php_value(&t, "MAJOR_VERSION").or_else(|| t.split("MAJOR_VERSION = ").nth(1).map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect()));
        let parts: Vec<String> = ["MAJOR_VERSION = ", "MINOR_VERSION = ", "PATCH_VERSION = "]
            .iter()
            .filter_map(|m| t.split(m).nth(1).map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>()))
            .filter(|s| !s.is_empty())
            .collect();
        let version = if parts.len() == 3 { parts.join(".") } else { major.unwrap_or_default() };
        return Some(WebApp { kind: "joomla".into(), path, version, plugins: Vec::new() });
    }
    let drupal = dir.join("core/lib/Drupal.php");
    if drupal.is_file() {
        let version = php_value(&head(&drupal, 16384), "const VERSION")?;
        return Some(WebApp { kind: "drupal".into(), path, version, plugins: Vec::new() });
    }
    None
}

pub fn collect() -> Vec<WebApp> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = ROOTS.iter().map(|r| (PathBuf::from(r), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        seen += 1;
        if seen > MAX_DIRS {
            break;
        }
        if let Some(app) = detect(&dir) {
            out.push(app);
            continue; // an engine's own directories are not searched further
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name();
            let n = name.to_string_lossy();
            if ft.is_dir() && !ft.is_symlink() && !n.starts_with('.') && n != "node_modules" && n != "vendor" {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp_version() {
        assert_eq!(php_value("<?php\n$wp_version = '6.4.2';\n", "$wp_version").as_deref(), Some("6.4.2"));
        assert_eq!(php_value("const VERSION = \"10.2.3\";", "const VERSION").as_deref(), Some("10.2.3"));
    }

    #[test]
    fn plugin() {
        let h = "<?php\n/**\n * Plugin Name: Contact Form 7\n * Version: 5.9.3\n */";
        assert_eq!(plugin_header(h), Some(("Contact Form 7".into(), "5.9.3".into())));
    }
}
