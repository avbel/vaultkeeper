//! Prints sleep/wake and screen lock/unlock events until Ctrl-C.
//!
//! `cargo run -p vk-platform --example power_watch`, then lock the screen (Ctrl-Cmd-Q), unlock,
//! and sleep/wake the Mac.

// Printing the events is the whole point of this example.
#![allow(clippy::print_stdout)]

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRunLoopRun();
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _watcher = vk_platform::power::subscribe(tx)?;
    std::thread::spawn(move || {
        for event in rx {
            println!("{event:?}");
        }
    });
    println!("watching; lock the screen or sleep the Mac (Ctrl-C to quit)");
    // SAFETY: called on the main thread, which has no other run loop user here. Notifications
    // are delivered only through the main run loop, so this must run for events to arrive.
    unsafe { CFRunLoopRun() };
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("power events are macOS only");
}
