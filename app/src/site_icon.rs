//! Which host a login's icon belongs to, and turning the server's bytes into row-sized pixels.
//! Both run off the UI thread or are cheap enough for `row_data`.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io::Cursor,
    sync::Arc,
};

use image::{ImageReader, Limits, RgbaImage, imageops::FilterType};
use slint::{Image, Rgba8Pixel, SharedPixelBuffer};
use url::{Host, Url};

/// Favicons are at most a few hundred pixels; anything larger is refused before decoding.
const MAX_SOURCE_SIDE: u32 = 1024;
const MAX_DECODE_ALLOC: u64 = 16 << 20;
/// Decoded icons kept by the UI process, about 8 KB each at the default text size.
const MAX_IMAGES: usize = 300;

/// Where a host's icon is. Only hosts that were on screen get a slot.
#[derive(Clone)]
pub enum Slot {
    Queued,
    Loading,
    Ready(Image),
    Missing,
}

/// The decoded icons shared by every list of the UI process, keyed by host.
#[derive(Default)]
pub struct IconCache {
    slots: RefCell<HashMap<Arc<str>, Slot>>,
    /// The hosts on screen at the last settle; eviction never drops them.
    on_screen: RefCell<HashSet<Arc<str>>>,
}

impl IconCache {
    #[must_use]
    pub fn image(&self, host: &str) -> Option<Image> {
        match self.slots.borrow().get(host) {
            Some(Slot::Ready(image)) => Some(image.clone()),
            _ => None,
        }
    }

    #[must_use]
    pub fn has(&self, host: &str) -> bool {
        self.slots.borrow().contains_key(host)
    }

    /// Nothing loaded or loading: rows need not look up their host at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.borrow().is_empty()
    }

    pub fn set(&self, host: Arc<str>, slot: Slot) {
        let mut slots = self.slots.borrow_mut();
        if matches!(slot, Slot::Ready(_)) && slots.len() >= MAX_IMAGES {
            // The daemon still has the bytes, so an evicted icon comes back on a re-request.
            let on_screen = self.on_screen.borrow();
            slots.retain(|host, kept| {
                matches!(kept, Slot::Queued | Slot::Loading) || on_screen.contains(host)
            });
        }
        slots.insert(host, slot);
    }

    /// Lets `host` be requested again (its load failed for now).
    pub fn forget(&self, host: &str) {
        self.slots.borrow_mut().remove(host);
    }

    /// Records the hosts on screen and forgets queued hosts that scrolled away; loads in flight
    /// stay.
    pub fn show(&self, on_screen: &[Arc<str>]) {
        let wanted: HashSet<Arc<str>> = on_screen.iter().cloned().collect();
        self.slots
            .borrow_mut()
            .retain(|host, slot| !matches!(slot, Slot::Queued) || wanted.contains(host));
        *self.on_screen.borrow_mut() = wanted;
    }

    pub fn clear(&self) {
        self.slots.borrow_mut().clear();
        self.on_screen.borrow_mut().clear();
    }
}

/// The host whose icon a login shows, following the official clients' `buildCipherIcon`: a bare
/// `example.com` counts as a website, otherwise only `http(s)` URIs with a dotted host do. App
/// URIs, IP addresses, `.onion` and `.i2p` get none.
#[must_use]
pub fn icon_host(uri: &str) -> Option<String> {
    let uri = uri.trim();
    if uri.starts_with("androidapp://") || uri.starts_with("iosapp://") || !uri.contains('.') {
        return None;
    }
    let url = if uri.contains("://") {
        Url::parse(uri).ok()?
    } else {
        Url::parse(&format!("http://{uri}")).ok()?
    };
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let Some(Host::Domain(host)) = url.host() else {
        return None;
    };
    let hidden = matches!(host.rsplit('.').next(), Some("onion" | "i2p"));
    (host.contains('.') && !hidden).then(|| host.to_owned())
}

/// Decodes `bytes` and scales the image to fit `side` x `side` pixels, so the renderer draws it
/// 1:1 instead of rescaling it on every frame. The pixels come back premultiplied: scaling
/// straight alpha would darken the edges of a transparent icon. `None` for anything that does
/// not decode.
#[must_use]
pub fn decode(bytes: &[u8], side: u32) -> Option<SharedPixelBuffer<Rgba8Pixel>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_SIDE);
    limits.max_image_height = Some(MAX_SOURCE_SIDE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);
    let mut rgba = reader.decode().ok()?.into_rgba8();
    let (width, height) = fit(rgba.width(), rgba.height(), side.max(1))?;
    premultiply(&mut rgba);
    // Triangle never overshoots, so a channel stays at or below its alpha.
    let rgba = if (width, height) == rgba.dimensions() {
        rgba
    } else {
        image::imageops::resize(&rgba, width, height, FilterType::Triangle)
    };
    Some(SharedPixelBuffer::clone_from_slice(
        rgba.as_raw(),
        rgba.width(),
        rgba.height(),
    ))
}

/// `width` x `height` scaled so the longer side is `side`, keeping the aspect ratio.
fn fit(width: u32, height: u32, side: u32) -> Option<(u32, u32)> {
    let longer = u64::from(width.max(height));
    if longer == 0 {
        return None;
    }
    let scale = |length: u32| {
        let scaled = (u64::from(length) * u64::from(side) + longer / 2) / longer;
        u32::try_from(scaled.max(1)).unwrap_or(side)
    };
    Some((scale(width), scale(height)))
}

fn premultiply(image: &mut RgbaImage) {
    for pixel in image.pixels_mut() {
        let alpha = u16::from(pixel[3]);
        for channel in &mut pixel.0[..3] {
            // At most 255 * 255 / 255, so it fits back in a u8.
            *channel = u8::try_from((u16::from(*channel) * alpha + 127) / 255).unwrap_or(u8::MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use image::{ImageFormat, Rgba, RgbaImage};

    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = RgbaImage::from_pixel(width, height, Rgba([200, 30, 30, 255]));
        let mut bytes = Cursor::new(Vec::new());
        image.write_to(&mut bytes, ImageFormat::Png).expect("png");
        bytes.into_inner()
    }

    #[test]
    fn hosts_follow_the_official_clients() {
        assert_eq!(
            icon_host("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(icon_host("github.com").as_deref(), Some("github.com"));
        assert_eq!(
            icon_host(" HTTP://Accounts.Google.com:8443/x ").as_deref(),
            Some("accounts.google.com")
        );
        assert_eq!(icon_host("http://localhost:8080"), None, "no dot");
        assert_eq!(icon_host("https://192.168.1.10/admin"), None);
        assert_eq!(icon_host("ftp://files.example.com"), None);
        assert_eq!(icon_host("androidapp://com.example.app"), None);
        assert_eq!(icon_host("iosapp://com.example.app"), None);
        assert_eq!(icon_host("http://abc.onion"), None);
        assert_eq!(icon_host("http://site.i2p"), None);
        assert_eq!(icon_host("not a url"), None);
        assert_eq!(icon_host(""), None);
    }

    #[test]
    fn decodes_and_fits_the_row_size() {
        let small = decode(&png(16, 16), 44).expect("decoded");
        assert_eq!((small.width(), small.height()), (44, 44));
        let wide = decode(&png(128, 64), 44).expect("decoded");
        assert_eq!(
            (wide.width(), wide.height()),
            (44, 22),
            "keeps the aspect ratio"
        );
        let tall = decode(&png(44, 1000), 44).expect("decoded");
        assert_eq!(
            (tall.width(), tall.height()),
            (2, 44),
            "one side already fits"
        );
        let exact = decode(&png(44, 44), 44).expect("decoded");
        assert_eq!(exact.as_slice()[0], Rgba8Pixel::new(200, 30, 30, 255));
    }

    #[test]
    fn eviction_keeps_loads_in_flight_and_icons_on_screen() {
        let cache = IconCache::default();
        let shown = Image::from_rgba8(SharedPixelBuffer::new(1, 1));
        cache.set(Arc::from("shown.example"), Slot::Ready(shown.clone()));
        cache.set(Arc::from("loading.example"), Slot::Loading);
        cache.set(Arc::from("queued.example"), Slot::Queued);
        cache.show(&[Arc::from("shown.example"), Arc::from("queued.example")]);
        for n in 0..MAX_IMAGES {
            cache.set(Arc::from(format!("{n}.example")), Slot::Missing);
        }
        cache.set(Arc::from("new.example"), Slot::Ready(shown));
        assert!(cache.image("new.example").is_some());
        assert!(cache.image("shown.example").is_some(), "on screen");
        assert!(cache.has("loading.example") && cache.has("queued.example"));
        assert!(!cache.has("0.example"));
        cache.show(&[Arc::from("shown.example")]);
        assert!(
            !cache.has("queued.example"),
            "scrolled away before it loaded"
        );
        assert!(cache.has("loading.example"));
        cache.forget("loading.example");
        assert!(!cache.has("loading.example"));
    }

    #[test]
    fn scaled_transparent_edges_keep_their_colour() {
        let mut image = RgbaImage::from_pixel(16, 16, Rgba([0, 0, 0, 0]));
        for x in 4..12 {
            for y in 4..12 {
                image.put_pixel(x, y, Rgba([255, 0, 0, 255]));
            }
        }
        let mut bytes = Cursor::new(Vec::new());
        image.write_to(&mut bytes, ImageFormat::Png).expect("png");
        let pixels = decode(&bytes.into_inner(), 44).expect("decoded");
        let edges: Vec<_> = pixels
            .as_slice()
            .iter()
            .filter(|pixel| pixel.a > 0 && pixel.a < 255)
            .collect();
        assert!(!edges.is_empty(), "the edge is blended");
        assert!(
            edges
                .iter()
                .all(|pixel| pixel.r == pixel.a && pixel.g == 0 && pixel.b == 0),
            "premultiplied pure red, no dark fringe"
        );
    }

    #[test]
    fn refuses_garbage_and_huge_images() {
        assert!(decode(b"<html></html>", 44).is_none());
        assert!(decode(&png(2048, 16), 44).is_none());
    }
}
