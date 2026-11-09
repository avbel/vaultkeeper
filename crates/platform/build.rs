fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(target_os = "macos")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        swift::link();
    }
}

#[cfg(target_os = "macos")]
mod swift {
    use std::{env, path::PathBuf};

    const PACKAGE: &str = "VkPlatform";
    const MIN_MACOS: &str = "13.0";

    pub fn link() {
        swift_rs::SwiftLinker::new(MIN_MACOS)
            .with_package(PACKAGE, "swift")
            .link();
        // swift-rs recognises the Xcode 27 SwiftPM output layout only when `xcodebuild` exists.
        // With Command Line Tools alone it emits the legacy `<arch>-apple-macosx/<config>` search
        // path, which stays empty; the archive lands in `<build-path>/<config>` instead.
        let out_dir = env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
        let config = if env::var("DEBUG").as_deref() == Ok("true") {
            "debug"
        } else {
            "release"
        };
        let search = PathBuf::from(out_dir)
            .join("swift-rs")
            .join(PACKAGE)
            .join(config);
        println!("cargo:rustc-link-search=native={}", search.display());
    }
}
