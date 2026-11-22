//! Windows application compatibility databases (`.sdb`, installed with `sdbinst`): what is inside, without
//! judging — the control centre decides. A database may only block programs from starting (Windows itself ships such
//! ones with updates), or may make programs load foreign code (InjectDll, RedirectEXE, in-memory patches, a shim
//! DLL of its own), which is a known way to stay on a broken-into machine.
//!
//! Format: a 12-byte header (`sdbf`), then tags: 16-bit tag whose top nibble is the type — lists, strings and
//! binaries carry a 32-bit size; string references point into the string table.

use serde::Serialize;

const T_NULL: u16 = 0x1000;
const T_BYTE: u16 = 0x2000;
const T_WORD: u16 = 0x3000;
const T_DWORD: u16 = 0x4000;
const T_QWORD: u16 = 0x5000;
const T_STRINGREF: u16 = 0x6000;
const T_LIST: u16 = 0x7000;
const T_STRING: u16 = 0x8000;
const T_BINARY: u16 = 0x9000;

const TAG_SHIM: u16 = 0x7004;
const TAG_PATCH: u16 = 0x7005;
const TAG_EXE: u16 = 0x7007;
const TAG_SHIM_REF: u16 = 0x7009;
const TAG_PATCH_REF: u16 = 0x700A;
const TAG_LAYER: u16 = 0x700B;
const TAG_APPHELP: u16 = 0x700D;
const TAG_STRINGTABLE: u16 = 0x7801;
const TAG_STRINGTABLE_ITEM: u16 = 0x8801;
const TAG_NAME: u16 = 0x6001;
const TAG_COMMAND_LINE: u16 = 0x6008;
const TAG_DLLFILE: u16 = 0x600A;
const TAG_PATCH_BITS: u16 = 0x9002;

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Content {
    /// programs the database applies to (EXE entries)
    pub exes: Vec<String>,
    /// shims applied (SHIM_REF names), e.g. InjectDll, RedirectEXE
    pub shims: Vec<String>,
    /// shim DLLs the database itself defines (SHIM → DLLFILE)
    pub shim_dlls: Vec<String>,
    /// command lines given to shims (InjectDll takes the DLL path here), first ones only
    pub command_lines: Vec<String>,
    /// in-memory patches present
    pub patches: bool,
    /// compatibility layers referenced
    pub layers: u32,
    /// «do not run» / warning messages (APPHELP)
    pub blocks: u32,
    pub error: Option<String>,
}

struct Tag<'a> {
    tag: u16,
    data: &'a [u8],
}

fn tags(b: &[u8]) -> Result<Vec<Tag<'_>>, String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 2 <= b.len() {
        let tag = u16::from_le_bytes([b[off], b[off + 1]]);
        off += 2;
        let len = match tag & 0xF000 {
            T_NULL => 0,
            T_BYTE => 1,
            T_WORD => 2,
            T_DWORD | T_STRINGREF => 4,
            T_QWORD => 8,
            T_LIST | T_STRING | T_BINARY => {
                let s = b.get(off..off + 4).ok_or("truncated size")?;
                off += 4;
                u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize
            }
            _ => return Err(format!("unknown tag type {tag:#06x}")),
        };
        let data = b.get(off..off + len).ok_or("truncated data")?;
        out.push(Tag { tag, data });
        off += len;
    }
    Ok(out)
}

fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|c| *c != 0).collect();
    String::from_utf16_lossy(&w)
}

struct Walk<'a> {
    strings: &'a [u8],
    c: Content,
}

impl Walk<'_> {
    fn string(&self, t: &Tag) -> String {
        let off = t.data.get(..4).map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize).unwrap_or(usize::MAX);
        // a reference points at the item's text; its size is the 4 bytes before it
        let Some(sz) = off.checked_sub(4).and_then(|i| self.strings.get(i..off)) else { return String::new() };
        let n = u32::from_le_bytes([sz[0], sz[1], sz[2], sz[3]]) as usize;
        self.strings.get(off..off + n).map(utf16).unwrap_or_default()
    }

    fn text(&self, t: &Tag) -> String {
        if t.tag & 0xF000 == T_STRING { utf16(t.data) } else { self.string(t) }
    }

    fn name_in(&self, list: &[u8], name_tag: u16) -> Option<String> {
        tags(list).ok()?.iter().find(|t| t.tag == name_tag).map(|t| self.text(t))
    }

    fn list(&mut self, b: &[u8]) {
        let Ok(ts) = tags(b) else { return };
        for t in ts {
            match t.tag {
                TAG_EXE => {
                    if let Some(n) = self.name_in(t.data, TAG_NAME)
                        && self.c.exes.len() < 100
                        && !self.c.exes.contains(&n)
                    {
                        self.c.exes.push(n);
                    }
                }
                TAG_SHIM_REF => {
                    if let Some(n) = self.name_in(t.data, TAG_NAME)
                        && !self.c.shims.contains(&n)
                    {
                        self.c.shims.push(n);
                    }
                    if let Some(cl) = self.name_in(t.data, TAG_COMMAND_LINE)
                        && self.c.command_lines.len() < 5
                    {
                        self.c.command_lines.push(cl.chars().take(200).collect());
                    }
                }
                TAG_SHIM => {
                    if let Some(d) = self.name_in(t.data, TAG_DLLFILE)
                        && !self.c.shim_dlls.contains(&d)
                    {
                        self.c.shim_dlls.push(d);
                    }
                }
                TAG_PATCH | TAG_PATCH_REF | TAG_PATCH_BITS => self.c.patches = true,
                TAG_LAYER => self.c.layers += 1,
                TAG_APPHELP => self.c.blocks += 1,
                _ => {}
            }
            if t.tag & 0xF000 == T_LIST && t.tag != TAG_STRINGTABLE {
                self.list(t.data);
            }
        }
    }
}

pub fn parse(b: &[u8]) -> Content {
    if b.len() < 12 || &b[8..12] != b"sdbf" {
        return Content { error: Some("not a compatibility database".into()), ..Default::default() };
    }
    let body = &b[12..];
    let top = match tags(body) {
        Ok(t) => t,
        Err(e) => return Content { error: Some(e), ..Default::default() },
    };
    let strings = top.iter().find(|t| t.tag == TAG_STRINGTABLE).map(|t| t.data).unwrap_or(&[]);
    let mut w = Walk { strings, c: Content::default() };
    w.list(body);
    let _ = TAG_STRINGTABLE_ITEM;
    w.c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(tag: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend((inner.len() as u32).to_le_bytes());
        v.extend(inner);
        v
    }
    fn sref(tag: u16, off: u32) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend(off.to_le_bytes());
        v
    }
    fn wstr(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(|c| c.to_le_bytes()).collect()
    }

    /// `SDB_FILE=path cargo test sdb -- --ignored --nocapture` prints what a real database contains.
    #[test]
    #[ignore]
    fn file_from_env() {
        if let Ok(p) = std::env::var("SDB_FILE") {
            println!("{:#?}", parse(&std::fs::read(p).unwrap()));
        }
    }

    /// A database like the one Windows installs with updates: a block message for one program, a Microsoft shim DLL
    /// applied to another; and one that injects a DLL.
    #[test]
    fn block_only_and_injection() {
        let names = ["game.exe", "AcSpecfc.DLL", "SomeFix", "evil.exe", "InjectDll", r"C:\ProgramData\x.dll"];
        let mut table = Vec::new();
        let mut offs = Vec::new();
        for n in names {
            let item = list(TAG_STRINGTABLE_ITEM, &wstr(n));
            offs.push(table.len() as u32 + 6);
            table.extend(item);
        }
        let shim = list(TAG_SHIM, &[sref(TAG_NAME, offs[2]), sref(TAG_DLLFILE, offs[1])].concat());
        let lib = list(0x7002, &shim);
        let exe1 = list(TAG_EXE, &[sref(TAG_NAME, offs[0]), list(TAG_APPHELP, &[])].concat());
        let exe2 = list(TAG_EXE, &[sref(TAG_NAME, offs[3]), list(TAG_SHIM_REF, &[sref(TAG_NAME, offs[4]), sref(TAG_COMMAND_LINE, offs[5])].concat())].concat());
        let db = list(0x7001, &[lib, exe1, exe2].concat());
        let mut b = vec![3, 0, 0, 0, 0, 0, 0, 0];
        b.extend(b"sdbf");
        b.extend(db);
        b.extend(list(TAG_STRINGTABLE, &table));
        let c = parse(&b);
        assert_eq!(c.exes, vec!["game.exe", "evil.exe"]);
        assert_eq!(c.shims, vec!["InjectDll"]);
        assert_eq!(c.shim_dlls, vec!["AcSpecfc.DLL"]);
        assert_eq!(c.command_lines, vec![r"C:\ProgramData\x.dll"]);
        assert_eq!(c.blocks, 1);
        assert!(!c.patches && c.error.is_none());
        assert!(parse(b"nonsense").error.is_some());
    }
}
