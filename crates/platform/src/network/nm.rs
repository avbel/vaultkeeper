//! Portable half of the Linux network watcher: what NetworkManager's states and primary
//! connection mean. Kept free of zbus types so the mapping is unit-tested on every host.

use super::NetworkEvent;

pub(super) const NM_NAME: &str = "org.freedesktop.NetworkManager";
pub(super) const NM_PATH: &str = "/org/freedesktop/NetworkManager";
pub(super) const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// The `NMState` values: 10 asleep, 20 disconnected, 30 disconnecting, 50 local only and 60 site
/// only (no internet, such as a captive portal) are unusable; only 70 (global) is usable.
/// Connecting (40) and unknown (0) carry no signal: the final state follows.
pub(super) const fn event_for_state(state: u32) -> Option<NetworkEvent> {
    match state {
        10 | 20 | 30 | 50 | 60 => Some(NetworkEvent::Unusable),
        70 => Some(NetworkEvent::Usable),
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
        for state in [10, 20, 30, 50, 60] {
            assert_eq!(
                event_for_state(state),
                Some(NetworkEvent::Unusable),
                "{state}"
            );
        }
        assert_eq!(event_for_state(70), Some(NetworkEvent::Usable));
        for state in [0, 40, 80, 90, 100] {
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
