use crate::security::{Chain, ChainReport, Link, Probe, Required};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    DataControl,
    Portal,
    Plain,
}

impl LinkKind {
    pub const ALL: [Self; 3] = [Self::DataControl, Self::Portal, Self::Plain];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::DataControl => "ext-data-control",
            Self::Portal => "portal-clipboard",
            Self::Plain => "plain",
        }
    }

    #[must_use]
    pub const fn mechanism(self) -> &'static str {
        match self {
            Self::DataControl => "Wayland data-control with the secret hint",
            Self::Portal => "RemoteDesktop + Clipboard portal",
            Self::Plain => "plain clipboard (history managers may record it)",
        }
    }
}

/// What each link's probe found; the real ones run at startup, tests inject fakes.
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub data_control: Probe,
    pub portal: Probe,
    pub plain: Probe,
}

impl Capabilities {
    fn probe(&self, kind: LinkKind) -> &Probe {
        match kind {
            LinkKind::DataControl => &self.data_control,
            LinkKind::Portal => &self.portal,
            LinkKind::Plain => &self.plain,
        }
    }

    /// The same capabilities with one link's probe replaced.
    #[must_use]
    pub fn with(&self, kind: LinkKind, probe: Probe) -> Self {
        let mut next = self.clone();
        match kind {
            LinkKind::DataControl => next.data_control = probe,
            LinkKind::Portal => next.portal = probe,
            LinkKind::Plain => next.plain = probe,
        }
        next
    }

    /// Links that can take a copy, strongest first.
    #[must_use]
    pub fn usable(&self) -> Vec<LinkKind> {
        LinkKind::ALL
            .into_iter()
            .filter(|kind| !matches!(self.probe(*kind), Probe::Unavailable(_)))
            .collect()
    }

    #[must_use]
    pub fn why_none_works(&self) -> String {
        LinkKind::ALL
            .into_iter()
            .filter_map(|kind| match self.probe(kind) {
                Probe::Unavailable(why) => Some(format!("{}: {why}", kind.id())),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[must_use]
    pub fn chain(&self) -> Chain {
        Chain {
            id: "clipboard",
            name: "Clipboard",
            required: Required::Status,
            // The portal route is what works on GNOME, which has no data-control, so it is
            // Standard; only the plain link is Reduced.
            minimum: 1,
            links: LinkKind::ALL
                .into_iter()
                .map(|kind| {
                    let probe = self.probe(kind).clone();
                    Link::new(kind.id(), kind.mechanism(), move || probe.clone())
                })
                .collect(),
            fix: Some(
                "Use a compositor with ext-data-control (KDE, Sway, Hyprland) or allow the \
                 clipboard permission prompt on GNOME."
                    .into(),
            ),
        }
    }

    #[must_use]
    pub fn report(&self) -> ChainReport {
        self.chain().evaluate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn data_control_wins_when_advertised() {
        let caps = caps(true, true, true);
        assert_eq!(caps.usable().first(), Some(&LinkKind::DataControl));
        assert_eq!(
            caps.report().active.as_deref(),
            Some(LinkKind::DataControl.mechanism())
        );
    }

    #[test]
    fn gnome_without_data_control_takes_the_portal() {
        let caps = caps(false, true, true);
        assert_eq!(caps.usable(), [LinkKind::Portal, LinkKind::Plain]);
        let report = caps.report();
        assert_eq!(report.active.as_deref(), Some(LinkKind::Portal.mechanism()));
        assert_eq!(report.status, crate::security::ChainStatus::Standard);
    }

    #[test]
    fn plain_is_reduced() {
        let report = caps(false, false, true).report();
        assert_eq!(report.active.as_deref(), Some(LinkKind::Plain.mechanism()));
        assert_eq!(report.status, crate::security::ChainStatus::Reduced);
        assert!(report.fix.is_some());
    }

    #[test]
    fn full_only_with_the_strongest_link() {
        assert_eq!(
            caps(true, false, false).report().status,
            crate::security::ChainStatus::Full
        );
    }

    #[test]
    fn nothing_works_names_every_reason() {
        let caps = caps(false, false, false);
        assert_eq!(caps.usable(), Vec::<LinkKind>::new());
        assert_eq!(caps.report().status, crate::security::ChainStatus::Off);
        let why = caps.why_none_works();
        assert!(why.contains("ext-data-control: missing") && why.contains("plain: missing"));
    }
}
