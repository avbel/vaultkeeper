//! Pure mappings from vault types to what the Slint views display.

use bwl_vault::{
    Error,
    model::{AccountView, CopyField, ItemKind, ItemSummary, SessionState},
};
use slint::SharedString;
use url::Url;

use crate::ui::{AccountRow, RowData};

/// TOTP code shown in a row; `expires` is in the UI clock's seconds (see `Clock.now`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCell {
    pub code: SharedString,
    pub expires: i32,
    pub period: i32,
}

/// Order of the "+ New" menu and of ⌘1…⌘5.
pub const NEW_KINDS: [ItemKind; 5] = [
    ItemKind::Login,
    ItemKind::SecureNote,
    ItemKind::Card,
    ItemKind::Identity,
    ItemKind::SshKey,
];

/// ⌘1…⌘5 per the keyboard spec: login, card, identity, note, SSH key.
pub const SHORTCUT_KINDS: [ItemKind; 5] = [
    ItemKind::Login,
    ItemKind::Card,
    ItemKind::Identity,
    ItemKind::SecureNote,
    ItemKind::SshKey,
];

#[must_use]
pub const fn kind_code(kind: ItemKind) -> i32 {
    match kind {
        ItemKind::Login => 0,
        ItemKind::SecureNote => 1,
        ItemKind::Card => 2,
        ItemKind::Identity => 3,
        ItemKind::SshKey => 4,
        ItemKind::Unsupported(_) => 5,
    }
}

#[must_use]
pub const fn kind_label(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "Login",
        ItemKind::SecureNote => "Secure note",
        ItemKind::Card => "Card",
        ItemKind::Identity => "Identity",
        ItemKind::SshKey => "SSH key",
        ItemKind::Unsupported(_) => "Unsupported item",
    }
}

const CUSTOM_BASE: i32 = 100;

#[must_use]
pub fn copy_code(field: CopyField) -> i32 {
    match field {
        CopyField::Username => 0,
        CopyField::Password => 1,
        CopyField::Totp => 2,
        CopyField::Uri => 3,
        CopyField::Notes => 4,
        CopyField::CardNumber => 5,
        CopyField::CardCode => 6,
        CopyField::Email => 7,
        CopyField::Phone => 8,
        CopyField::SshPublicKey => 9,
        CopyField::SshPrivateKey => 10,
        CopyField::Custom(index) => {
            CUSTOM_BASE.saturating_add(i32::try_from(index).unwrap_or(i32::MAX - CUSTOM_BASE))
        }
    }
}

#[must_use]
pub fn copy_field(code: i32) -> Option<CopyField> {
    Some(match code {
        0 => CopyField::Username,
        1 => CopyField::Password,
        2 => CopyField::Totp,
        3 => CopyField::Uri,
        4 => CopyField::Notes,
        5 => CopyField::CardNumber,
        6 => CopyField::CardCode,
        7 => CopyField::Email,
        8 => CopyField::Phone,
        9 => CopyField::SshPublicKey,
        10 => CopyField::SshPrivateKey,
        code if code >= CUSTOM_BASE => CopyField::Custom(usize::try_from(code - CUSTOM_BASE).ok()?),
        _ => return None,
    })
}

#[must_use]
pub const fn copy_label(field: CopyField) -> &'static str {
    match field {
        CopyField::Username => "username",
        CopyField::Password => "password",
        CopyField::Totp => "TOTP",
        CopyField::Uri => "URI",
        CopyField::Notes => "notes",
        CopyField::CardNumber => "card number",
        CopyField::CardCode => "security code",
        CopyField::Email => "email",
        CopyField::Phone => "phone",
        CopyField::SshPublicKey => "public key",
        CopyField::SshPrivateKey => "private key",
        CopyField::Custom(_) => "field",
    }
}

/// The two always-visible copy buttons of a list row.
#[must_use]
pub fn row_buttons(item: &ItemSummary) -> [Option<CopyField>; 2] {
    match item.kind {
        ItemKind::Login => [
            (!item.subtitle.is_empty()).then_some(CopyField::Username),
            item.has_password.then_some(CopyField::Password),
        ],
        ItemKind::Card => [Some(CopyField::CardNumber), Some(CopyField::CardCode)],
        ItemKind::Identity => [Some(CopyField::Email), Some(CopyField::Phone)],
        ItemKind::SshKey => [
            Some(CopyField::SshPublicKey),
            Some(CopyField::SshPrivateKey),
        ],
        ItemKind::SecureNote => [Some(CopyField::Notes), None],
        ItemKind::Unsupported(_) => [None, None],
    }
}

fn button(field: Option<CopyField>) -> (i32, SharedString) {
    field.map_or((-1, SharedString::new()), |field| {
        (
            copy_code(field),
            format!("Copy {}", copy_label(field)).into(),
        )
    })
}

#[must_use]
pub fn to_row(item: &ItemSummary, totp: Option<&TotpCell>) -> RowData {
    let [first, second] = row_buttons(item);
    let (b1, b1_label) = button(first);
    let (b2, b2_label) = button(second);
    RowData {
        kind: kind_code(item.kind),
        name: item.name.as_ref().into(),
        subtitle: item.subtitle.as_ref().into(),
        favorite: item.favorite,
        reprompt: item.reprompt,
        b1,
        b2,
        b1_label,
        b2_label,
        has_totp: item.has_totp && item.kind == ItemKind::Login,
        totp_code: totp.map(|cell| cell.code.clone()).unwrap_or_default(),
        totp_expires: totp.map_or(0, |cell| cell.expires),
        totp_period: totp.map_or(30, |cell| cell.period),
        auto_type: crate::autotype::can_auto_type(item),
    }
}

/// `482913` → `482 913`, `12345678` → `1234 5678`; other lengths (Steam's 5 letters) unchanged.
#[must_use]
pub fn group_code(code: &str) -> String {
    let len = code.chars().count();
    if !(len == 6 || len == 8) || !code.is_ascii() {
        return code.to_owned();
    }
    let (left, right) = code.split_at(len / 2);
    format!("{left} {right}")
}

/// Decimal units, as Finder shows them.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes;
    let mut unit = 0;
    // Tenths of the unit, kept in integers to avoid float rounding surprises.
    let mut tenths = value / 100;
    while value >= 1_000_000 && unit < UNITS.len() - 1 {
        value /= 1000;
        unit += 1;
        tenths = value / 100;
    }
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit])
}

#[must_use]
pub fn synced_text(seconds_ago: Option<u64>) -> String {
    match seconds_ago {
        None => "Not synced yet".to_owned(),
        Some(0..60) => "Synced just now".to_owned(),
        Some(seconds @ 60..3600) => format!("Synced {} min ago", seconds / 60),
        Some(seconds @ 3600..86_400) => format!("Synced {} h ago", seconds / 3600),
        Some(seconds) => format!("Synced {} d ago", seconds / 86_400),
    }
}

#[must_use]
pub fn status_line(
    seconds_since_sync: Option<u64>,
    offline: bool,
    items: usize,
    ssh_keys: Option<usize>,
) -> String {
    let sync = if offline {
        "Offline — cached vault".to_owned()
    } else {
        synced_text(seconds_since_sync)
    };
    let items = if items == 1 {
        "1 item".to_owned()
    } else {
        format!("{items} items")
    };
    match ssh_keys {
        Some(1) => format!("{sync} · {items} · SSH agent: 1 key"),
        Some(keys) => format!("{sync} · {items} · SSH agent: {keys} keys"),
        None => format!("{sync} · {items} · SSH agent off"),
    }
}

#[must_use]
pub fn error_text(error: &Error) -> String {
    match error {
        Error::Locked => "The vault is locked".to_owned(),
        Error::LoggedOut => "Not logged in".to_owned(),
        Error::InvalidPassword => "Wrong master password".to_owned(),
        Error::NotFound => "Item not found".to_owned(),
        Error::NoSuchField => "Nothing to copy".to_owned(),
        Error::ReadOnly => "This item is read-only".to_owned(),
        Error::Api(api) => api_error_text(api),
        Error::Crypto(_) => "Decryption failed".to_owned(),
        Error::Gen(error) => error.to_string(),
        Error::Io(error) => format!("Storage error: {error}"),
        Error::Cache(_) => "The local cache is damaged; sync again".to_owned(),
        Error::Offline => bwl_vault::OFFLINE_MESSAGE.to_owned(),
        Error::Conflict => bwl_vault::CONFLICT_MESSAGE.to_owned(),
        Error::KdfDowngrade => bwl_vault::KDF_DOWNGRADE_MESSAGE.to_owned(),
        Error::Logout(errors) => match errors.0.as_slice() {
            [only] => format!("Logged out, but one step failed: {}", error_text(only)),
            steps => format!("Logged out, but {} steps failed", steps.len()),
        },
    }
}

fn api_error_text(error: &bwl_api::Error) -> String {
    if error.is_offline() && !matches!(error, bwl_api::Error::Server { .. }) {
        return CANT_REACH.to_owned();
    }
    match error {
        bwl_api::Error::Http(_) | bwl_api::Error::Io(_) => CANT_REACH.to_owned(),
        bwl_api::Error::UntrustedUrl(host) => format!("Blocked a request to untrusted host {host}"),
        bwl_api::Error::Tls(detail) => tls_text(detail),
        bwl_api::Error::Decode(_) => NOT_COMPATIBLE.to_owned(),
        bwl_api::Error::Url(_) => "Not a valid server URL".to_owned(),
        bwl_api::Error::InvalidServerUrl(reason) => format!("Server URL refused: {reason}"),
        bwl_api::Error::Server { message, .. } => message.clone(),
        bwl_api::Error::Unauthorized => "Session expired; log in again".to_owned(),
    }
}

fn tls_text(detail: &str) -> String {
    format!("Secure connection failed: {detail}")
}

pub const CANT_REACH: &str = "Can't reach server";
pub const NOT_COMPATIBLE: &str = "Not a Bitwarden-compatible server";

/// Where a login failure is shown: under the server field or as the form's general error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    Server(String),
    General(String),
}

#[must_use]
pub fn login_error(error: &Error) -> LoginError {
    if error.is_offline() {
        return LoginError::Server(CANT_REACH.to_owned());
    }
    match error {
        Error::Api(bwl_api::Error::Http(_) | bwl_api::Error::Io(_)) => {
            LoginError::Server(CANT_REACH.to_owned())
        }
        Error::Api(
            bwl_api::Error::Decode(_)
            | bwl_api::Error::Server {
                status: 404 | 405, ..
            },
        ) => LoginError::Server(NOT_COMPATIBLE.to_owned()),
        Error::Api(bwl_api::Error::Url(_)) => LoginError::Server("Not a valid URL".to_owned()),
        Error::Api(bwl_api::Error::Tls(detail)) => LoginError::Server(tls_text(detail)),
        Error::InvalidPassword => LoginError::General("Wrong email or master password".to_owned()),
        other => LoginError::General(error_text(other)),
    }
}

/// The login screen's line under the server URL, and whether it is good news.
#[must_use]
pub fn probe_text(result: &bwl_vault::Result<bwl_vault::model::ServerProbe>) -> (String, bool) {
    match result {
        Ok(probe) => match &probe.version {
            Some(version) => (format!("Reachable · Vaultwarden {version}"), true),
            None => ("Reachable".to_owned(), true),
        },
        Err(error) => match login_error(error) {
            LoginError::Server(text) | LoginError::General(text) => (text, false),
        },
    }
}

#[must_use]
pub fn host(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => url.as_str().to_owned(),
    }
}

#[must_use]
pub fn initial(email: &str) -> String {
    email
        .chars()
        .next()
        .map_or_else(|| "?".to_owned(), |first| first.to_uppercase().collect())
}

/// Stable avatar colour per email; mid-saturation hues that read on light and dark surfaces.
#[must_use]
pub fn avatar_color(email: &str) -> slint::Color {
    const PALETTE: [(u8, u8, u8); 6] = [
        (0x3B, 0x82, 0xF6),
        (0x8B, 0x5C, 0xF6),
        (0x14, 0xB8, 0xA6),
        (0xF5, 0x9E, 0x0B),
        (0x22, 0xC5, 0x5E),
        (0xEC, 0x48, 0x99),
    ];
    let hash = email
        .to_lowercase()
        .bytes()
        .fold(0x811c_9dc5_u32, |hash, byte| {
            (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
        });
    let (red, green, blue) = PALETTE[usize::try_from(hash).unwrap_or(0) % PALETTE.len()];
    slint::Color::from_rgb_u8(red, green, blue)
}

#[must_use]
pub fn account_badge(account: &AccountView, state: &SessionState) -> &'static str {
    if !account.logged_in {
        return "logged out";
    }
    if account.active && matches!(state, SessionState::Unlocked { .. }) {
        return "";
    }
    "locked"
}

#[must_use]
pub fn account_rows(accounts: &[AccountView], state: &SessionState) -> Vec<AccountRow> {
    accounts
        .iter()
        .map(|account| AccountRow {
            email: account.email.as_ref().into(),
            host: host(&account.server).into(),
            initial: initial(&account.email).into(),
            color: avatar_color(&account.email),
            active: account.active,
            badge: account_badge(account, state).into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bwl_vault::model::ItemId;

    use super::*;

    fn item(kind: ItemKind, subtitle: &str, has_password: bool, has_totp: bool) -> ItemSummary {
        ItemSummary {
            id: ItemId(Arc::from("id")),
            kind,
            name: Arc::from("GitHub"),
            subtitle: Arc::from(subtitle),
            favorite: true,
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            has_password,
            has_totp,
            reprompt: false,
            deleted: false,
            editable: true,
        }
    }

    #[test]
    fn copy_codes_round_trip_and_match_the_slint_table() {
        let fields = [
            (CopyField::Username, 0),
            (CopyField::Password, 1),
            (CopyField::Totp, 2),
            (CopyField::Uri, 3),
            (CopyField::Notes, 4),
            (CopyField::CardNumber, 5),
            (CopyField::CardCode, 6),
            (CopyField::Email, 7),
            (CopyField::Phone, 8),
            (CopyField::SshPublicKey, 9),
            (CopyField::SshPrivateKey, 10),
            (CopyField::Custom(0), 100),
            (CopyField::Custom(3), 103),
        ];
        for (field, code) in fields {
            assert_eq!(copy_code(field), code, "{field:?}");
            assert_eq!(copy_field(code), Some(field), "{code}");
        }
        assert_eq!(copy_field(-1), None);
        assert_eq!(copy_field(11), None);
        assert_eq!(copy_field(99), None);
    }

    #[test]
    fn row_buttons_per_kind_follow_the_spec() {
        let login = item(ItemKind::Login, "octocat", true, true);
        assert_eq!(
            row_buttons(&login),
            [Some(CopyField::Username), Some(CopyField::Password)]
        );
        let no_user = item(ItemKind::Login, "", true, false);
        assert_eq!(row_buttons(&no_user), [None, Some(CopyField::Password)]);
        let card = item(ItemKind::Card, "Visa ····4242", false, false);
        assert_eq!(
            row_buttons(&card),
            [Some(CopyField::CardNumber), Some(CopyField::CardCode)]
        );
        let identity = item(ItemKind::Identity, "a@b.c", false, false);
        assert_eq!(
            row_buttons(&identity),
            [Some(CopyField::Email), Some(CopyField::Phone)]
        );
        let ssh = item(ItemKind::SshKey, "SHA256:x", false, false);
        assert_eq!(
            row_buttons(&ssh),
            [
                Some(CopyField::SshPublicKey),
                Some(CopyField::SshPrivateKey)
            ]
        );
        let note = item(ItemKind::SecureNote, "", false, false);
        assert_eq!(row_buttons(&note), [Some(CopyField::Notes), None]);
        let other = item(ItemKind::Unsupported(7), "", false, false);
        assert_eq!(row_buttons(&other), [None, None]);
    }

    #[test]
    fn to_row_maps_fields_and_totp_overlay() {
        let login = item(ItemKind::Login, "octocat", true, true);
        let row = to_row(&login, None);
        assert_eq!(row.name, "GitHub");
        assert_eq!(row.subtitle, "octocat");
        assert_eq!((row.b1, row.b2), (0, 1));
        assert_eq!(row.b1_label, "Copy username");
        assert_eq!(row.b2_label, "Copy password");
        assert!(row.has_totp);
        assert_eq!(row.totp_code, "");
        let cell = TotpCell {
            code: "482 913".into(),
            expires: 40,
            period: 30,
        };
        let row = to_row(&login, Some(&cell));
        assert_eq!(row.totp_code, "482 913");
        assert_eq!((row.totp_expires, row.totp_period), (40, 30));
        let card = to_row(&item(ItemKind::Card, "Visa", false, true), None);
        assert!(!card.has_totp, "only logins show a TOTP cell");
        assert_eq!(card.kind, 2);
    }

    #[test]
    fn groups_totp_codes() {
        assert_eq!(group_code("482913"), "482 913");
        assert_eq!(group_code("12345678"), "1234 5678");
        assert_eq!(group_code("2BX7P"), "2BX7P");
        assert_eq!(group_code(""), "");
    }

    #[test]
    fn human_sizes_use_decimal_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1000), "1.0 KB");
        assert_eq!(human_size(1234), "1.2 KB");
        assert_eq!(human_size(999_999), "999.9 KB");
        assert_eq!(human_size(2_500_000), "2.5 MB");
        assert_eq!(human_size(3_000_000_000), "3.0 GB");
        // 18,446,744,073,709,551,615 B = 18,446,744.07 TB.
        assert_eq!(human_size(u64::MAX), "18446744.0 TB");
    }

    #[test]
    fn sync_and_status_text() {
        assert_eq!(synced_text(None), "Not synced yet");
        assert_eq!(synced_text(Some(5)), "Synced just now");
        assert_eq!(synced_text(Some(120)), "Synced 2 min ago");
        assert_eq!(synced_text(Some(7200)), "Synced 2 h ago");
        assert_eq!(synced_text(Some(172_800)), "Synced 2 d ago");
        assert_eq!(
            status_line(Some(120), false, 412, Some(2)),
            "Synced 2 min ago · 412 items · SSH agent: 2 keys"
        );
        assert_eq!(
            status_line(None, true, 1, None),
            "Offline — cached vault · 1 item · SSH agent off"
        );
    }

    #[test]
    fn error_messages() {
        assert_eq!(error_text(&Error::InvalidPassword), "Wrong master password");
        assert_eq!(error_text(&Error::ReadOnly), "This item is read-only");
        let server = Error::Api(bwl_api::Error::Server {
            status: 400,
            message: "Two-step token is invalid".to_owned(),
        });
        assert_eq!(error_text(&server), "Two-step token is invalid");
        let tls = Error::Api(bwl_api::Error::Tls(
            "the server's certificate has expired".to_owned(),
        ));
        let expected = "Secure connection failed: the server's certificate has expired";
        assert_eq!(error_text(&tls), expected);
        assert_eq!(login_error(&tls), LoginError::Server(expected.into()));
        assert_eq!(
            login_error(&server),
            LoginError::General("Two-step token is invalid".into())
        );
        let not_found = Error::Api(bwl_api::Error::Server {
            status: 404,
            message: "Not Found".to_owned(),
        });
        assert_eq!(
            login_error(&not_found),
            LoginError::Server(NOT_COMPATIBLE.into())
        );
        assert_eq!(
            login_error(&Error::InvalidPassword),
            LoginError::General("Wrong email or master password".into())
        );
        let gateway = Error::Api(bwl_api::Error::Server {
            status: 503,
            message: "Service Unavailable".to_owned(),
        });
        assert_eq!(login_error(&gateway), LoginError::Server(CANT_REACH.into()));
        assert_eq!(error_text(&gateway), "Service Unavailable");
        assert_eq!(
            login_error(&Error::Offline),
            LoginError::Server(CANT_REACH.into())
        );
        assert_eq!(error_text(&Error::Offline), bwl_vault::OFFLINE_MESSAGE);
    }

    #[test]
    fn probe_lines() {
        let found = Ok(bwl_vault::model::ServerProbe {
            version: Some("1.37.5".to_owned()),
        });
        assert_eq!(
            probe_text(&found),
            ("Reachable · Vaultwarden 1.37.5".to_owned(), true)
        );
        let bare = Ok(bwl_vault::model::ServerProbe { version: None });
        assert_eq!(probe_text(&bare), ("Reachable".to_owned(), true));
        assert_eq!(
            probe_text(&Err(Error::Offline)),
            (CANT_REACH.to_owned(), false)
        );
        let not_found = Err(Error::Api(bwl_api::Error::Server {
            status: 404,
            message: "Not Found".to_owned(),
        }));
        assert_eq!(probe_text(&not_found), (NOT_COMPATIBLE.to_owned(), false));
    }

    #[test]
    fn log_out_failures_are_summarised() {
        let one = Error::Logout(bwl_vault::LogoutErrors(vec![Error::Io(
            std::io::Error::other("keychain locked"),
        )]));
        assert_eq!(
            error_text(&one),
            "Logged out, but one step failed: Storage error: keychain locked"
        );
        let two = Error::Logout(bwl_vault::LogoutErrors(vec![
            Error::NotFound,
            Error::Locked,
        ]));
        assert_eq!(error_text(&two), "Logged out, but 2 steps failed");
    }

    #[test]
    fn accounts_and_hosts() {
        let url = Url::parse("https://vault.example.com:8443/").expect("url");
        assert_eq!(host(&url), "vault.example.com:8443");
        assert_eq!(initial("alice@example.com"), "A");
        assert_eq!(initial(""), "?");
        let account = |active, logged_in| AccountView {
            id: Arc::from("a"),
            server: Url::parse("https://vault.example.com").expect("url"),
            email: Arc::from("alice@example.com"),
            active,
            logged_in,
        };
        let unlocked = SessionState::Unlocked {
            server: Url::parse("https://vault.example.com").expect("url"),
            email: "alice@example.com".into(),
        };
        assert_eq!(account_badge(&account(true, true), &unlocked), "");
        assert_eq!(account_badge(&account(false, true), &unlocked), "locked");
        assert_eq!(
            account_badge(&account(false, false), &unlocked),
            "logged out"
        );
        assert_eq!(
            account_badge(&account(true, true), &SessionState::LoggedOut),
            "locked"
        );
        let rows = account_rows(&[account(true, true)], &unlocked);
        assert_eq!(rows[0].email, "alice@example.com");
        assert_eq!(rows[0].host, "vault.example.com");
        assert_eq!(rows[0].initial, "A");
        assert_eq!(
            rows[0].color,
            avatar_color("ALICE@example.com"),
            "case-insensitive"
        );
        assert!(rows[0].active);
    }
}
