//! Link 1: `ext-data-control-v1` (or wlr-data-control) through wl-clipboard-rs.

use std::time::{Duration, Instant};

use wl_clipboard_rs::{copy, paste};
use zeroize::Zeroizing;

use super::ClipboardBackend;
use crate::{
    Error, Result,
    pipe_read::{self, Bounded},
    security::Probe,
};

const TEXT_MIME: &str = "text/plain;charset=utf-8";
/// A paste owner that never answers must not hold the clipboard lock for good.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Far above anything Vaultkeeper copies (Bitwarden caps a note at 10 000 characters, at most
/// 40 KB of UTF-8), so a larger clipboard cannot hold our copy and is left alone.
const READ_LIMIT: usize = 1024 * 1024;

pub struct DataControl;

pub fn probe() -> Probe {
    match paste::get_mime_types(paste::ClipboardType::Regular, paste::Seat::Unspecified) {
        Ok(_) | Err(paste::Error::ClipboardEmpty | paste::Error::NoMimeType) => Probe::Available,
        Err(error) => Probe::Unavailable(error.to_string()),
    }
}

fn error(error: &impl std::fmt::Display) -> Error {
    Error::Clipboard(error.to_string())
}

impl ClipboardBackend for DataControl {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        let mut options = copy::Options::new();
        // Offers `x-kde-passwordManagerHint=secret`, which Klipper and the Omarchy history skip.
        options.sensitive(true);
        // The library keeps its own copy of the bytes until the selection is replaced or cleared,
        // and that copy cannot be zeroized from here.
        options
            .copy(
                copy::Source::Bytes(text.as_bytes().into()),
                copy::MimeType::Specific(TEXT_MIME.to_owned()),
            )
            .map_err(|failure| error(&failure))
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        let reader = match paste::get_contents(
            paste::ClipboardType::Regular,
            paste::Seat::Unspecified,
            paste::MimeType::Text,
        ) {
            Ok((reader, _)) => reader,
            Err(
                paste::Error::ClipboardEmpty | paste::Error::NoMimeType | paste::Error::NoSeats,
            ) => return Ok(None),
            Err(failure) => return Err(error(&failure)),
        };
        match pipe_read::read_bounded(reader, READ_LIMIT, Instant::now() + READ_TIMEOUT)? {
            Bounded::Complete(bytes) => {
                let text = std::str::from_utf8(&bytes).map_err(|failure| error(&failure))?;
                Ok(Some(Zeroizing::new(text.to_owned())))
            }
            Bounded::TooLarge => Ok(None),
            Bounded::TimedOut => Err(Error::Clipboard(
                "the clipboard owner did not answer".into(),
            )),
        }
    }

    fn clear(&mut self) -> Result<()> {
        copy::clear(copy::ClipboardType::Regular, copy::Seat::All)
            .map_err(|failure| error(&failure))
    }
}
