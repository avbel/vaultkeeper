use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Element debug info is what the testing backend's ElementHandle queries use; release builds
    // skip it to keep the binary small.
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile == "debug");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile Slint UI");

    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        embed_windows_resources();
    }
}

// Splits the workspace version into the four 16-bit fields VERSIONINFO needs, padding with zeros
// and ignoring any pre-release or build-metadata suffix (e.g. "0.1.10-rc.1" -> 0,1,10,0).
fn version_quad(version: &str) -> (u16, u16, u16, u16) {
    let numeric = version.split('-').next().unwrap_or(version);
    let mut parts = numeric.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

// rc.exe and llvm-rc accept forward-slash paths, so Windows backslashes must be flipped before
// they are embedded in a resource string literal.
fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn embed_windows_resources() {
    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is set by Cargo");
    let (maj, min, pat, bld) = version_quad(&version);
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo");
    let windows = Path::new(&manifest_dir)
        .join("..")
        .join("packaging")
        .join("windows");
    let manifest = slash(&windows.join("vaultkeeper.manifest"));
    let icon = slash(&windows.join("vaultkeeper.ico"));

    // 24 is RT_MANIFEST, which needs winuser.h to be named; the numeric form keeps llvm-rc from
    // requiring the Windows SDK headers during cross-checks.
    let rc = format!(
        r#"1 24 "{manifest}"
1 ICON "{icon}"

1 VERSIONINFO
FILEVERSION {maj},{min},{pat},{bld}
PRODUCTVERSION {maj},{min},{pat},{bld}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Vaultkeeper"
            VALUE "FileDescription", "Vaultkeeper"
            VALUE "FileVersion", "{version}"
            VALUE "InternalName", "vaultkeeper"
            VALUE "OriginalFilename", "vaultkeeper.exe"
            VALUE "ProductName", "Vaultkeeper"
            VALUE "ProductVersion", "{version}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
    );

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is set by Cargo");
    let rc_path = Path::new(&out_dir).join("vaultkeeper.rc");
    fs::write(&rc_path, rc).expect("write generated resource script");
    embed_resource::compile(&rc_path, embed_resource::NONE)
        .manifest_required()
        .expect("embed Windows resources");
}
