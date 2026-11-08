mod ui {
    #![allow(clippy::all, clippy::pedantic, clippy::unwrap_used)]
    slint::include_modules!();
}

use slint::ComponentHandle;

fn main() -> anyhow::Result<()> {
    let window = ui::AppWindow::new()?;
    window.run()?;
    Ok(())
}
