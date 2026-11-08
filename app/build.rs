fn main() {
    // Element debug info is what the testing backend's ElementHandle queries use; release builds
    // skip it to keep the binary small.
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile == "debug");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile Slint UI");
}
