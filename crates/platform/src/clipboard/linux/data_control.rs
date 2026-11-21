//! Link 1: `ext-data-control-v1` (or wlr-data-control) through wl-clipboard-rs.

use std::{sync::mpsc, time::Duration};

use wl_clipboard_rs::{copy, paste};
use zeroize::Zeroizing;

use super::ClipboardBackend;
use crate::{Error, Result, security::Probe};

const TEXT_MIME: &str = "text/plain;charset=utf-8";
/// A paste owner that never answers must not hold the clipboard lock for good.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

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
        let bytes = read_with_timeout(reader)?;
        let text = std::str::from_utf8(&bytes).map_err(|failure| error(&failure))?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }

    fn clear(&mut self) -> Result<()> {
        copy::clear(copy::ClipboardType::Regular, copy::Seat::All)
            .map_err(|failure| error(&failure))
    }
}

fn read_with_timeout(
    mut reader: impl std::io::Read + Send + 'static,
) -> Result<Zeroizing<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("vk-clipboard-read".into())
        .spawn(move || {
            let mut bytes = Zeroizing::new(Vec::new());
            let read = reader.read_to_end(&mut bytes).map(|_| bytes);
            drop(sender.send(read));
        })?;
    match receiver.recv_timeout(READ_TIMEOUT) {
        Ok(read) => read.map_err(Error::Io),
        Err(_) => Err(Error::Clipboard(
            "the clipboard owner did not answer".into(),
        )),
    }
}
