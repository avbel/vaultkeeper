//! Link 3: arboard (X11 through XWayland), a plain set.

use arboard::SetExtLinux as _;
use zeroize::Zeroizing;

use super::ClipboardBackend;
use crate::{Error, Result};

pub struct Plain(arboard::Clipboard);

pub fn open() -> std::result::Result<Plain, String> {
    arboard::Clipboard::new()
        .map(Plain)
        .map_err(|error| error.to_string())
}

fn error(error: &arboard::Error) -> Error {
    Error::Clipboard(error.to_string())
}

impl ClipboardBackend for Plain {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        self.0
            .set()
            .exclude_from_history()
            .text(text)
            .map_err(|failure| error(&failure))
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        match self.0.get_text() {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(failure) => Err(error(&failure)),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.0.clear().map_err(|failure| error(&failure))
    }
}
