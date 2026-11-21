use zeroize::Zeroizing;

use super::{
    ClipboardBackend,
    chain::{Capabilities, LinkKind},
};
use crate::{
    Error, Result,
    security::{ChainReport, Probe},
};

/// The backends that exist on this machine, whether or not their probe passed.
#[derive(Default)]
pub struct Parts {
    pub data_control: Option<Box<dyn ClipboardBackend>>,
    pub portal: Option<Box<dyn ClipboardBackend>>,
    pub plain: Option<Box<dyn ClipboardBackend>>,
}

impl Parts {
    fn take(&mut self, kind: LinkKind) -> Option<Box<dyn ClipboardBackend>> {
        match kind {
            LinkKind::DataControl => self.data_control.take(),
            LinkKind::Portal => self.portal.take(),
            LinkKind::Plain => self.plain.take(),
        }
    }
}

/// The links that probed as usable, strongest first. A copy goes to the first that accepts it, so
/// a denied portal prompt lands on the plain link; reads and clears go to the link that took the
/// last copy.
pub struct LinuxClipboard {
    links: Vec<(LinkKind, Box<dyn ClipboardBackend>)>,
    holder: Option<usize>,
    capabilities: Capabilities,
    report: ChainReport,
}

impl LinuxClipboard {
    pub fn assemble(capabilities: &Capabilities, mut parts: Parts) -> Result<Self> {
        let links: Vec<_> = capabilities
            .usable()
            .into_iter()
            .filter_map(|kind| parts.take(kind).map(|backend| (kind, backend)))
            .collect();
        if links.is_empty() {
            return Err(Error::Clipboard(format!(
                "no clipboard mechanism works here ({})",
                capabilities.why_none_works()
            )));
        }
        Ok(Self {
            links,
            holder: None,
            report: capabilities.report(),
            capabilities: capabilities.clone(),
        })
    }

    pub const fn report(&self) -> &ChainReport {
        &self.report
    }

    /// The link that holds the last copy.
    #[cfg(test)]
    pub fn holder(&self) -> Option<LinkKind> {
        self.holder.map(|index| self.links[index].0)
    }
}

impl ClipboardBackend for LinuxClipboard {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        let mut last = Error::Unsupported;
        let mut capabilities = self.capabilities.clone();
        let mut taken = None;
        for (index, (kind, backend)) in self.links.iter_mut().enumerate() {
            match backend.set_secret(text) {
                Ok(()) => {
                    capabilities = capabilities.with(*kind, Probe::Available);
                    taken = Some(index);
                    break;
                }
                Err(error) => {
                    tracing::warn!(link = kind.id(), %error, "clipboard link refused the copy");
                    capabilities = capabilities.with(*kind, Probe::Unavailable(error.to_string()));
                    last = error;
                }
            }
        }
        // What a link can really do is only known once it was tried, so the report follows.
        self.report = capabilities.report();
        self.capabilities = capabilities;
        self.holder = taken.or(self.holder);
        taken.map_or(Err(last), |_| Ok(()))
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        match self.holder {
            Some(index) => self.links[index].1.text(),
            None => Ok(None),
        }
    }

    fn clear(&mut self) -> Result<()> {
        match self.holder {
            Some(index) => self.links[index].1.clear(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Fake {
        content: Arc<Mutex<Option<String>>>,
        refuses: bool,
    }

    impl Fake {
        fn content(&self) -> Option<String> {
            self.content.lock().expect("lock").clone()
        }
    }

    impl ClipboardBackend for Fake {
        fn set_secret(&mut self, text: &str) -> Result<()> {
            if self.refuses {
                return Err(Error::Clipboard("denied".into()));
            }
            *self.content.lock().expect("lock") = Some(text.to_owned());
            Ok(())
        }

        fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
            Ok(self.content().map(Zeroizing::new))
        }

        fn clear(&mut self) -> Result<()> {
            *self.content.lock().expect("lock") = None;
            Ok(())
        }
    }

    fn caps(data_control: bool, portal: bool, plain: bool) -> Capabilities {
        let probe = |works: bool| {
            if works {
                Probe::Available
            } else {
                Probe::Unavailable("missing".into())
            }
        };
        Capabilities {
            data_control: probe(data_control),
            portal: probe(portal),
            plain: probe(plain),
        }
    }

    fn parts(data_control: &Fake, portal: &Fake, plain: &Fake) -> Parts {
        Parts {
            data_control: Some(Box::new(data_control.clone())),
            portal: Some(Box::new(portal.clone())),
            plain: Some(Box::new(plain.clone())),
        }
    }

    #[test]
    fn copies_through_the_strongest_usable_link_only() {
        let (dc, portal, plain) = (Fake::default(), Fake::default(), Fake::default());
        let mut clipboard =
            LinuxClipboard::assemble(&caps(true, true, true), parts(&dc, &portal, &plain))
                .expect("assemble");
        clipboard.set_secret("hunter2").expect("copy");
        assert_eq!(clipboard.holder(), Some(LinkKind::DataControl));
        assert_eq!(dc.content().as_deref(), Some("hunter2"));
        assert_eq!((portal.content(), plain.content()), (None, None));
    }

    #[test]
    fn a_link_whose_probe_failed_is_never_used() {
        let (dc, portal, plain) = (Fake::default(), Fake::default(), Fake::default());
        let mut clipboard =
            LinuxClipboard::assemble(&caps(false, true, true), parts(&dc, &portal, &plain))
                .expect("assemble");
        clipboard.set_secret("hunter2").expect("copy");
        assert_eq!(clipboard.holder(), Some(LinkKind::Portal));
        assert_eq!(dc.content(), None);
    }

    #[test]
    fn a_denied_portal_falls_back_to_the_plain_link_and_clears_there() {
        let denied = Fake {
            refuses: true,
            ..Fake::default()
        };
        let (dc, plain) = (Fake::default(), Fake::default());
        let mut clipboard =
            LinuxClipboard::assemble(&caps(false, true, true), parts(&dc, &denied, &plain))
                .expect("assemble");
        clipboard.set_secret("hunter2").expect("copy");
        assert_eq!(clipboard.holder(), Some(LinkKind::Plain));
        assert_eq!(
            clipboard.report().active.as_deref(),
            Some(LinkKind::Plain.mechanism()),
            "the report follows the failed portal"
        );
        assert_eq!(
            clipboard.report().status,
            crate::security::ChainStatus::Reduced
        );
        assert_eq!(
            clipboard
                .text()
                .expect("read")
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
        clipboard.clear().expect("clear");
        assert_eq!(plain.content(), None);
    }

    #[test]
    fn every_link_refusing_reports_the_last_error() {
        let refuses = Fake {
            refuses: true,
            ..Fake::default()
        };
        let mut clipboard = LinuxClipboard::assemble(
            &caps(true, false, true),
            parts(&refuses, &refuses, &refuses),
        )
        .expect("assemble");
        assert!(matches!(
            clipboard.set_secret("hunter2"),
            Err(Error::Clipboard(_))
        ));
        assert_eq!(clipboard.holder(), None);
        assert!(clipboard.text().expect("read").is_none());
    }

    #[test]
    fn no_usable_link_refuses_to_assemble_and_says_why() {
        let none = Fake::default();
        let Err(Error::Clipboard(why)) =
            LinuxClipboard::assemble(&caps(false, false, false), parts(&none, &none, &none))
        else {
            panic!("expected a clipboard error");
        };
        assert!(why.contains("ext-data-control: missing"));
    }

    #[test]
    fn the_report_names_the_active_link() {
        let none = Fake::default();
        let clipboard =
            LinuxClipboard::assemble(&caps(false, false, true), parts(&none, &none, &none))
                .expect("assemble");
        assert_eq!(
            clipboard.report().active.as_deref(),
            Some(LinkKind::Plain.mechanism())
        );
    }
}
