//! Windows: file details (company, product, version) in the exe, so that it is not an anonymous binary. No packers.
//! Built with the MSVC target through cargo-xwin; the resource compiler is llvm-rc.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let v = env!("CARGO_PKG_VERSION");
    let nums: Vec<u16> = v.split('.').map(|x| x.parse().unwrap_or(0)).chain(std::iter::repeat(0)).take(4).collect();
    let comma = format!("{},{},{},{}", nums[0], nums[1], nums[2], nums[3]);
    let rc = format!(
        r#"#include <winver.h>
1 VERSIONINFO
FILEVERSION {comma}
PRODUCTVERSION {comma}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "GTVA s.r.o."
      VALUE "ProductName", "HT CYBERCOP agent"
      VALUE "FileDescription", "HT CYBERCOP agent"
      VALUE "LegalCopyright", "GTVA s.r.o., Apache-2.0"
      VALUE "FileVersion", "{v}"
      VALUE "ProductVersion", "{v}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
    );
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("version.rc");
    fs::write(&out, rc).unwrap();
    embed_resource::compile(&out, embed_resource::NONE).manifest_required().unwrap();
}
