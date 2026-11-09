//! Deterministic sample vaults for the mock accounts.

use std::{collections::HashMap, sync::Arc};

use bwl_vault::model::{
    AttachmentView, CollectionView, CustomField, FolderView, IdentityData, ItemData, ItemDraft,
    ItemId, ItemKind, ItemSummary, OrganizationView,
};
use zeroize::Zeroizing;

use super::fake::{Prng, fake_ssh_key, fnv1a};

pub struct MockItem {
    pub summary: ItemSummary,
    pub draft: ItemDraft,
    pub name_lower: String,
    pub subtitle_lower: String,
    pub uri_lower: String,
    pub last_used: u64,
}

#[derive(Default)]
pub struct AccountData {
    pub items: Vec<MockItem>,
    pub folders: Vec<FolderView>,
    pub organizations: Vec<OrganizationView>,
    pub collections: Vec<CollectionView>,
    pub attachments: HashMap<ItemId, Vec<AttachmentView>>,
}

/// Derives the list row from the draft, as the real vault does after decrypting names.
#[must_use]
pub fn summarize(id: &ItemId, draft: &ItemDraft, editable: bool, deleted: bool) -> ItemSummary {
    let (kind, subtitle, primary_uri, has_password, has_totp) = match &draft.data {
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        } => (
            ItemKind::Login,
            username.clone(),
            uris.first().cloned(),
            !password.is_empty(),
            !totp.is_empty(),
        ),
        ItemData::SecureNote => (ItemKind::SecureNote, String::new(), None, false, false),
        ItemData::Card { brand, number, .. } => {
            let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
            let last4: String = digits[digits.len().saturating_sub(4)..].iter().collect();
            (
                ItemKind::Card,
                format!("{brand} ····{last4}"),
                None,
                false,
                false,
            )
        }
        ItemData::Identity(identity) => (
            ItemKind::Identity,
            identity.email.clone(),
            None,
            false,
            false,
        ),
        ItemData::SshKey { fingerprint, .. } => {
            (ItemKind::SshKey, fingerprint.clone(), None, false, false)
        }
    };
    ItemSummary {
        id: id.clone(),
        kind,
        name: Arc::from(draft.name.as_str()),
        subtitle: Arc::from(subtitle),
        favorite: draft.favorite,
        folder_id: draft.folder_id.clone(),
        organization_id: draft.organization_id.clone(),
        primary_uri: primary_uri.map(Arc::from),
        has_password,
        has_totp,
        reprompt: draft.reprompt,
        deleted,
        editable,
    }
}

impl MockItem {
    #[must_use]
    pub fn new(id: &ItemId, draft: ItemDraft, editable: bool, deleted: bool) -> Self {
        let summary = summarize(id, &draft, editable, deleted);
        Self::from_parts(summary, draft)
    }

    #[must_use]
    pub fn from_parts(summary: ItemSummary, draft: ItemDraft) -> Self {
        Self {
            name_lower: summary.name.to_lowercase(),
            subtitle_lower: summary.subtitle.to_lowercase(),
            uri_lower: summary
                .primary_uri
                .as_deref()
                .unwrap_or_default()
                .to_lowercase(),
            summary,
            draft,
            last_used: 0,
        }
    }
}

fn empty_draft(name: &str, data: ItemData) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        notes: Zeroizing::new(String::new()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data,
        revision_date: Some(Arc::from(SEED_REVISION)),
    }
}

/// The revision every seeded item starts at; saves move it on like the server's `revisionDate`.
pub const SEED_REVISION: &str = "2026-01-01T00:00:00.000Z";

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn fake_password(prng: &mut Prng) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    (0..16).map(|_| char::from(*prng.pick(CHARS))).collect()
}

fn login(name: &str, username: &str, uri: &str, prng: &mut Prng, totp: bool) -> ItemDraft {
    empty_draft(
        name,
        ItemData::Login {
            username: username.to_owned(),
            password: Zeroizing::new(fake_password(prng)),
            totp: secret(if totp { "JBSWY3DPEHPK3PXP" } else { "" }),
            uris: if uri.is_empty() {
                Vec::new()
            } else {
                vec![uri.to_owned()]
            },
        },
    )
}

const SITES: [(&str, &str); 60] = [
    ("GitHub", "github.com"),
    ("AWS Console", "console.aws.amazon.com"),
    ("Gmail", "mail.google.com"),
    ("Amazon", "amazon.com"),
    ("Netflix", "netflix.com"),
    ("Dropbox", "dropbox.com"),
    ("Slack", "slack.com"),
    ("Notion", "notion.so"),
    ("Figma", "figma.com"),
    ("Linear", "linear.app"),
    ("GitLab", "gitlab.com"),
    ("Docker Hub", "hub.docker.com"),
    ("npm", "npmjs.com"),
    ("crates.io", "crates.io"),
    ("Cloudflare", "dash.cloudflare.com"),
    ("DigitalOcean", "cloud.digitalocean.com"),
    ("Hetzner", "console.hetzner.cloud"),
    ("Stripe", "dashboard.stripe.com"),
    ("PayPal", "paypal.com"),
    ("Revolut", "app.revolut.com"),
    ("N26", "app.n26.com"),
    ("Booking.com", "booking.com"),
    ("Airbnb", "airbnb.com"),
    ("Lufthansa", "lufthansa.com"),
    ("Deutsche Bahn", "bahn.de"),
    ("Spotify", "spotify.com"),
    ("Apple ID", "appleid.apple.com"),
    ("Microsoft", "login.live.com"),
    ("LinkedIn", "linkedin.com"),
    ("Mastodon", "mastodon.social"),
    ("Reddit", "reddit.com"),
    ("Hacker News", "news.ycombinator.com"),
    ("Discord", "discord.com"),
    ("Zoom", "zoom.us"),
    ("1und1", "1und1.de"),
    ("Namecheap", "namecheap.com"),
    ("Fastmail", "fastmail.com"),
    ("Proton Mail", "account.proton.me"),
    ("Backblaze", "secure.backblaze.com"),
    ("Tailscale", "login.tailscale.com"),
    ("Grafana Cloud", "grafana.com"),
    ("Sentry", "sentry.io"),
    ("Datadog", "app.datadoghq.eu"),
    ("Vercel", "vercel.com"),
    ("Netlify", "app.netlify.com"),
    ("Heroku", "dashboard.heroku.com"),
    ("Jira", "acme.atlassian.net"),
    ("Confluence", "acme.atlassian.net/wiki"),
    ("Home router", "192.168.1.1"),
    ("Synology NAS", "nas.local:5001"),
    ("Proxmox", "pve.local:8006"),
    ("Grafana (home)", "grafana.local"),
    ("Steam", "store.steampowered.com"),
    ("Nintendo", "accounts.nintendo.com"),
    ("eBay", "ebay.de"),
    ("IKEA", "ikea.com"),
    ("Strava", "strava.com"),
    ("Duolingo", "duolingo.com"),
    ("Kindle", "read.amazon.com"),
    ("Wikipedia", "wikipedia.org"),
];

const USERS: [&str; 6] = [
    "alice",
    "alice.smith",
    "asmith",
    "alice@example.com",
    "octocat",
    "admin",
];

struct Ids {
    prefix: &'static str,
    next: u64,
}

impl Ids {
    fn next(&mut self) -> ItemId {
        self.next += 1;
        ItemId(Arc::from(format!("{}-{:04}", self.prefix, self.next)))
    }
}

fn folder(id: &str, name: &str) -> FolderView {
    FolderView {
        id: Arc::from(id),
        name: Arc::from(name),
    }
}

/// About 400 items for the main demo account.
#[must_use]
pub fn alice() -> AccountData {
    let mut prng = Prng::new(fnv1a("alice@example.com"));
    let mut ids = Ids {
        prefix: "alice",
        next: 0,
    };
    let folders = vec![
        folder("f-personal", "Personal"),
        folder("f-work", "Work"),
        folder("f-infra", "Work/Infra"),
        folder("f-finance", "Finance"),
        folder("f-shopping", "Shopping"),
        folder("f-social", "Social"),
        folder("f-travel", "Travel"),
        folder("f-dev", "Dev"),
    ];
    let org = Arc::<str>::from("org-acme");
    let mut data = AccountData {
        organizations: vec![OrganizationView {
            id: Arc::clone(&org),
            name: Arc::from("Acme Corp"),
        }],
        collections: vec![
            CollectionView {
                id: Arc::from("col-eng"),
                organization_id: Arc::clone(&org),
                name: Arc::from("Engineering"),
                read_only: false,
            },
            CollectionView {
                id: Arc::from("col-ops"),
                organization_id: Arc::clone(&org),
                name: Arc::from("Operations"),
                read_only: false,
            },
            CollectionView {
                id: Arc::from("col-fin"),
                organization_id: Arc::clone(&org),
                name: Arc::from("Finance"),
                read_only: true,
            },
        ],
        ..AccountData::default()
    };
    push_logins(&mut data, &mut prng, &mut ids, &folders);
    push_org_items(&mut data, &mut prng, &mut ids, &org);
    push_cards(&mut data, &mut prng, &mut ids);
    push_identities(&mut data, &mut ids);
    push_notes(&mut data, &mut prng, &mut ids);
    push_ssh_keys(&mut data, &mut ids);
    push_specials(&mut data, &mut ids);
    data.folders = folders;
    seed_mru(&mut data);
    data
}

fn push_logins(data: &mut AccountData, prng: &mut Prng, ids: &mut Ids, folders: &[FolderView]) {
    for round in 0..5 {
        for (site, host) in SITES {
            let name = match round {
                0 => site.to_owned(),
                1 => format!("{site} (work)"),
                2 => format!("{site} (old)"),
                3 => format!("{site} — family"),
                _ => format!("{site} test account"),
            };
            let username = if round == 1 {
                "alice@acme.example"
            } else {
                prng.pick(&USERS)
            };
            let uri = format!("https://{host}");
            let totp = prng.chance(25);
            let mut draft = login(&name, username, &uri, prng, totp);
            draft.folder_id = prng.chance(70).then(|| Arc::clone(&prng.pick(folders).id));
            draft.favorite = round == 0 && prng.chance(15);
            draft.reprompt = round == 0 && site == "PayPal";
            if draft.reprompt {
                // A re-prompt item with every gated kind of field: notes and a TOTP.
                draft.notes = Zeroizing::new("Security answer: blue heron".to_owned());
                if let ItemData::Login { totp, .. } = &mut draft.data {
                    *totp = Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned());
                }
            }
            if prng.chance(10) {
                draft.fields.push(CustomField {
                    name: "Recovery PIN".to_owned(),
                    value: Zeroizing::new(format!("{:04}", prng.below(10_000))),
                    hidden: true,
                });
            }
            data.items
                .push(MockItem::new(&ids.next(), draft, true, false));
        }
    }
}

fn push_org_items(data: &mut AccountData, prng: &mut Prng, ids: &mut Ids, org: &Arc<str>) {
    for (index, (site, host)) in SITES.iter().take(24).enumerate() {
        let finance = index % 3 == 0;
        let uri = format!("https://{host}");
        let mut draft = login(
            &format!("Acme {site}"),
            "ops@acme.example",
            &uri,
            prng,
            index % 4 == 0,
        );
        draft.organization_id = Some(Arc::clone(org));
        draft.collection_ids = vec![Arc::from(if finance { "col-fin" } else { "col-eng" })];
        data.items
            .push(MockItem::new(&ids.next(), draft, !finance, false));
    }
}

fn push_cards(data: &mut AccountData, prng: &mut Prng, ids: &mut Ids) {
    const CARDS: [(&str, &str); 4] = [
        ("Visa", "4242 4242 4242 4242"),
        ("Mastercard", "5555 5555 5555 4444"),
        ("Amex", "3782 822463 10005"),
        ("Visa", "4000 0566 5566 5556"),
    ];
    for index in 0..20 {
        let (brand, number) = CARDS[index % CARDS.len()];
        let name = match index {
            0 => "Personal Visa".to_owned(),
            1 => "Business Mastercard".to_owned(),
            _ => format!("{brand} card {}", index + 1),
        };
        let draft = ItemDraft {
            favorite: index == 0,
            folder_id: Some(Arc::from("f-finance")),
            ..empty_draft(
                &name,
                ItemData::Card {
                    cardholder_name: "Alice Smith".to_owned(),
                    brand: brand.to_owned(),
                    number: secret(number),
                    exp_month: format!("{:02}", 1 + prng.below(12)),
                    exp_year: format!("{}", 2027 + prng.below(5)),
                    code: Zeroizing::new(format!("{:03}", prng.below(1000))),
                },
            )
        };
        data.items
            .push(MockItem::new(&ids.next(), draft, true, false));
    }
}

fn push_identities(data: &mut AccountData, ids: &mut Ids) {
    const PEOPLE: [(&str, &str); 5] = [
        ("Alice", "Smith"),
        ("Robert", "Smith"),
        ("Emma", "Smith"),
        ("Grandma", "Jones"),
        ("Alice", "Smith (work)"),
    ];
    for index in 0..15 {
        let (first, last) = PEOPLE[index % PEOPLE.len()];
        let name = if index < PEOPLE.len() {
            format!("{first} {last}")
        } else {
            format!("{first} {last} #{}", index + 1)
        };
        let identity = IdentityData {
            title: "Ms".to_owned(),
            first_name: first.to_owned(),
            last_name: last.to_owned(),
            email: format!("{}@example.com", first.to_lowercase()),
            phone: format!("+49 30 5550{index:03}"),
            address1: format!("{} Example Street", 10 + index),
            city: "Berlin".to_owned(),
            postal_code: "10115".to_owned(),
            country: "DE".to_owned(),
            ssn: secret("123-45-6789"),
            passport_number: Zeroizing::new(format!("C01X00T4{index}")),
            ..IdentityData::default()
        };
        let draft = empty_draft(&name, ItemData::Identity(Box::new(identity)));
        data.items
            .push(MockItem::new(&ids.next(), draft, true, false));
    }
}

fn push_notes(data: &mut AccountData, prng: &mut Prng, ids: &mut Ids) {
    const TOPICS: [&str; 10] = [
        "Server runbook",
        "Wi-Fi guest network",
        "Recovery codes",
        "Alarm system",
        "Lockbox combination",
        "Insurance policy",
        "Car service history",
        "Kubernetes on-call",
        "Bike lock",
        "Home inventory",
    ];
    for index in 0..40 {
        let topic = TOPICS[index % TOPICS.len()];
        let name = if index < TOPICS.len() {
            topic.to_owned()
        } else {
            format!("{topic} ({})", index / TOPICS.len() + 1)
        };
        let draft = ItemDraft {
            notes: Zeroizing::new(format!(
                "{topic}\n\nReference {:06}. Keep this note up to date.",
                prng.below(1_000_000)
            )),
            folder_id: (index % 2 == 0).then(|| Arc::from("f-personal")),
            ..empty_draft(&name, ItemData::SecureNote)
        };
        data.items
            .push(MockItem::new(&ids.next(), draft, true, false));
    }
}

fn push_ssh_keys(data: &mut AccountData, ids: &mut Ids) {
    const KEYS: [&str; 6] = [
        "deploy-ed25519",
        "github-signing",
        "homelab",
        "backup-server",
        "ci-runner",
        "laptop-2024",
    ];
    for index in 0..12 {
        let name = KEYS[index % KEYS.len()];
        let name = if index < KEYS.len() {
            name.to_owned()
        } else {
            format!("{name}-old")
        };
        let (private_key, public_key, fingerprint) =
            fake_ssh_key(fnv1a(&name), &format!("alice@{name}"));
        let draft = ItemDraft {
            folder_id: Some(Arc::from("f-dev")),
            ..empty_draft(
                &name,
                ItemData::SshKey {
                    private_key,
                    public_key,
                    fingerprint,
                },
            )
        };
        data.items
            .push(MockItem::new(&ids.next(), draft, true, false));
    }
}

fn attachment(id: &str, name: &str, size_bytes: u64) -> AttachmentView {
    AttachmentView {
        id: Arc::from(id),
        file_name: Arc::from(name),
        size_bytes,
    }
}

fn find(data: &AccountData, name: &str) -> Option<ItemId> {
    data.items
        .iter()
        .find(|item| item.summary.name.as_ref() == name)
        .map(|item| item.summary.id.clone())
}

fn push_specials(data: &mut AccountData, ids: &mut Ids) {
    let trashed = login(
        "Old router login",
        "admin",
        "http://192.168.0.1",
        &mut Prng::new(3),
        false,
    );
    data.items
        .push(MockItem::new(&ids.next(), trashed, true, true));
    let mut unsupported = empty_draft("Passkey placeholder", ItemData::SecureNote);
    unsupported.notes = secret("Item type not supported by bw-lite");
    let mut item = MockItem::new(&ids.next(), unsupported, false, false);
    item.summary.kind = ItemKind::Unsupported(6);
    data.items.push(item);
    for (name, files) in [
        (
            "Server runbook",
            vec![attachment("att-runbook", "runbook.pdf", 248_000)],
        ),
        (
            "AWS Console",
            vec![attachment("att-aws", "credentials.csv", 1_234)],
        ),
        (
            "Alice Smith",
            vec![
                attachment("att-passport", "passport-scan.jpg", 1_830_000),
                attachment("att-id", "id-card.png", 412_000),
            ],
        ),
    ] {
        if let Some(id) = find(data, name) {
            data.attachments.insert(id, files);
        }
    }
}

fn seed_mru(data: &mut AccountData) {
    const RECENT: [&str; 10] = [
        "GitHub",
        "AWS Console",
        "Gmail",
        "Personal Visa",
        "Slack",
        "Server runbook",
        "Alice Smith",
        "deploy-ed25519",
        "Hetzner",
        "Tailscale",
    ];
    for (rank, name) in RECENT.iter().enumerate() {
        if let Some(item) = data
            .items
            .iter_mut()
            .find(|item| item.summary.name.as_ref() == *name)
        {
            item.last_used = 1_000 - u64::try_from(rank).unwrap_or(0);
        }
    }
}

/// A smaller work vault for the second account; no names overlap with [`alice`].
#[must_use]
pub fn bob() -> AccountData {
    const WORK: [(&str, &str); 12] = [
        ("Corp SSO", "sso.work.example.org"),
        ("Corp VPN", "vpn.work.example.org"),
        ("Build farm", "ci.work.example.org"),
        ("HR portal", "hr.work.example.org"),
        ("Expense tool", "expenses.work.example.org"),
        ("Wiki", "wiki.work.example.org"),
        ("Ticket desk", "desk.work.example.org"),
        ("Artifact store", "artifacts.work.example.org"),
        ("Payroll", "payroll.work.example.org"),
        ("Badge office", "badge.work.example.org"),
        ("Staging DB", "db-staging.work.example.org"),
        ("Prod DB", "db-prod.work.example.org"),
    ];
    let mut prng = Prng::new(fnv1a("bob@work.example.org"));
    let mut ids = Ids {
        prefix: "bob",
        next: 0,
    };
    let mut data = AccountData {
        folders: vec![folder("fb-ops", "Operations"), folder("fb-admin", "Admin")],
        ..AccountData::default()
    };
    for round in 0..3 {
        for (site, host) in WORK {
            let name = if round == 0 {
                site.to_owned()
            } else {
                format!("{site} #{round}")
            };
            let mut draft = login(
                &name,
                "bob.builder",
                &format!("https://{host}"),
                &mut prng,
                round == 0,
            );
            draft.folder_id = Some(Arc::from(if round == 2 { "fb-admin" } else { "fb-ops" }));
            data.items
                .push(MockItem::new(&ids.next(), draft, true, false));
        }
    }
    let note = ItemDraft {
        notes: secret("Escalation: page the on-call lead, then the duty manager."),
        ..empty_draft("On-call escalation", ItemData::SecureNote)
    };
    data.items
        .push(MockItem::new(&ids.next(), note, true, false));
    data
}

/// The vault created for an account added through the login screen.
#[must_use]
pub fn fresh(email: &str) -> AccountData {
    let mut prng = Prng::new(fnv1a(email));
    let mut ids = Ids {
        prefix: "new",
        next: fnv1a(email) % 1000 * 100,
    };
    let mut data = AccountData::default();
    let draft = login(
        "Welcome login",
        email,
        "https://vault.example.com",
        &mut prng,
        false,
    );
    data.items
        .push(MockItem::new(&ids.next(), draft, true, false));
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_has_about_400_items_of_every_kind() {
        let data = alice();
        assert!(
            (380..=440).contains(&data.items.len()),
            "{}",
            data.items.len()
        );
        for kind in [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SshKey,
            ItemKind::Unsupported(6),
        ] {
            assert!(
                data.items.iter().any(|item| item.summary.kind == kind),
                "{kind:?}"
            );
        }
        assert!(data.items.iter().any(|item| item.summary.has_totp));
        assert!(
            data.items
                .iter()
                .any(|item| item.summary.kind == ItemKind::Login && !item.summary.has_totp)
        );
        assert!(data.items.iter().any(|item| item.summary.deleted));
        assert!(
            data.items
                .iter()
                .any(|item| item.summary.organization_id.is_some())
        );
        assert!(data.items.iter().any(|item| !item.summary.editable));
        assert_eq!(data.attachments.values().map(Vec::len).sum::<usize>(), 4);
        let ids: std::collections::HashSet<_> = data
            .items
            .iter()
            .map(|item| item.summary.id.clone())
            .collect();
        assert_eq!(ids.len(), data.items.len(), "ids are unique");
    }

    #[test]
    fn bob_shares_no_item_names_with_alice() {
        let alice_names: std::collections::HashSet<String> = alice()
            .items
            .iter()
            .map(|item| item.summary.name.to_string())
            .collect();
        assert!(
            bob()
                .items
                .iter()
                .all(|item| !alice_names.contains(item.summary.name.as_ref()))
        );
    }

    #[test]
    fn summaries_follow_the_draft() {
        let draft = empty_draft(
            "Visa",
            ItemData::Card {
                cardholder_name: String::new(),
                brand: "Visa".to_owned(),
                number: secret("4242 4242 4242 4242"),
                exp_month: String::new(),
                exp_year: String::new(),
                code: secret(""),
            },
        );
        let summary = summarize(&ItemId(Arc::from("x")), &draft, true, false);
        assert_eq!(summary.subtitle.as_ref(), "Visa ····4242");
        assert_eq!(summary.kind, ItemKind::Card);
    }
}
