//! Portable half of the Linux network watcher: what NetworkManager's states and primary
//! connection mean. Kept free of zbus types so the mapping is unit-tested on every host.

use super::NetworkEvent;

pub(super) const NM_NAME: &str = "org.freedesktop.NetworkManager";
pub(super) const NM_PATH: &str = "/org/freedesktop/NetworkManager";
pub(super) const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// The `NMState` values. Connecting and unknown states carry no signal: the final state follows.
pub(super) const fn event_for_state(state: u32) -> Option<NetworkEvent> {
    match state {
        10..=30 => Some(NetworkEvent::Unusable),
        70 | 80 | 90 => Some(NetworkEvent::Usable),
        _ => None,
    }
}

/// `PrimaryConnection` is the object path of the active connection carrying the default route;
/// NetworkManager uses `/` for none.
pub(super) fn event_for_primary(path: &str) -> NetworkEvent {
    if path == "/" {
        NetworkEvent::Unusable
    } else {
        NetworkEvent::Usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nm_states_map_to_events() {
        for state in [10, 20, 30] {
            assert_eq!(
                event_for_state(state),
                Some(NetworkEvent::Unusable),
                "{state}"
            );
        }
        for state in [70, 80, 90] {
            assert_eq!(
                event_for_state(state),
                Some(NetworkEvent::Usable),
                "{state}"
            );
        }
        for state in [0, 40, 50, 60, 100] {
            assert_eq!(event_for_state(state), None, "{state}");
        }
    }

    #[test]
    fn primary_connection_none_is_unusable() {
        assert_eq!(event_for_primary("/"), NetworkEvent::Unusable);
        assert_eq!(
            event_for_primary("/org/freedesktop/NetworkManager/ActiveConnection/3"),
            NetworkEvent::Usable
        );
    }
}
