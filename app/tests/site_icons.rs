//! Site icons on list rows: loaded only for the rows on screen once the list is still, and not
//! at all while "Show site icons" is off.

mod common;

use std::{
    io::Cursor,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use common::{Setup, click, elapse, harness, pump, set_size, type_into};
use image::{ImageFormat, Rgba, RgbaImage};
use slint::{ComponentHandle, Model};
use tokio::sync::oneshot;
use vaultkeeper::{
    app::BrowserPromptRequest,
    hooks::{IconLookup, SiteIcon, SiteIconSource},
    rows::RowsModel,
    settings::Settings,
    site_icon::icon_host,
    ui::{ManagerWindow, Theme},
};
use vk_ipc::{BrowserPrompt, dto::ItemSummaryDto};
use vk_vault::{
    VaultService,
    model::{Filter, ItemKind},
};

const SETTLE: Duration = Duration::from_millis(200);

#[derive(Default)]
struct FakeIcons {
    requested: Mutex<Vec<String>>,
    /// Answered with `Unavailable` (offline) while set.
    offline: AtomicBool,
}

impl FakeIcons {
    fn requested(&self) -> Vec<String> {
        self.requested.lock().expect("requests").clone()
    }
}

impl SiteIconSource for FakeIcons {
    fn fetch(&self, host: &str) -> IconLookup {
        self.requested
            .lock()
            .expect("requests")
            .push(host.to_owned());
        let image = RgbaImage::from_pixel(16, 16, Rgba([10, 120, 200, 255]));
        let mut png = Cursor::new(Vec::new());
        image.write_to(&mut png, ImageFormat::Png).expect("png");
        let bytes = png.into_inner();
        let offline = self.offline.load(Ordering::SeqCst);
        Box::pin(async move {
            if offline {
                SiteIcon::Unavailable
            } else {
                SiteIcon::Found(bytes)
            }
        })
    }
}

fn open() -> (common::Harness, ManagerWindow, Arc<FakeIcons>) {
    open_with(Settings::default(), FakeIcons::default())
}

fn open_with(
    settings: Settings,
    icons: FakeIcons,
) -> (common::Harness, ManagerWindow, Arc<FakeIcons>) {
    let icons = Arc::new(icons);
    let h = harness(Setup {
        settings,
        site_icons: Some(Arc::clone(&icons) as Arc<dyn SiteIconSource>),
        ..Setup::default()
    });
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    set_size(&manager, 1120.0, 520.0);
    pump();
    (h, manager, icons)
}

fn visible_hosts(manager: &ManagerWindow) -> Vec<String> {
    let first = usize::try_from(manager.get_first_visible()).expect("first");
    let count = usize::try_from(manager.get_visible_count()).expect("count");
    let rows = manager.get_rows();
    let model = rows
        .as_any()
        .downcast_ref::<RowsModel>()
        .expect("rows model");
    (first..first + count)
        .filter_map(|row| model.item(row))
        .filter(|item| item.kind == ItemKind::Login)
        .filter_map(|item| item.primary_uri.as_deref().and_then(icon_host))
        .collect()
}

fn icons_shown(manager: &ManagerWindow) -> usize {
    let rows = manager.get_rows();
    (0..rows.row_count())
        .filter_map(|row| rows.row_data(row))
        .filter(|row| row.icon.size().width > 0)
        .count()
}

#[test]
fn icons_load_for_the_rows_on_screen_after_the_list_settles() {
    let (_h, manager, icons) = open();
    assert!(
        icons.requested().is_empty(),
        "nothing before the list settles"
    );
    elapse(SETTLE);
    let requested = icons.requested();
    assert_ne!(
        requested,
        Vec::<String>::new(),
        "the rows on screen were requested"
    );
    let on_screen = visible_hosts(&manager);
    assert!(
        requested.iter().all(|host| on_screen.contains(host)),
        "{requested:?} not all in {on_screen:?}"
    );
    let mut unique = requested.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), requested.len(), "each host once");
    assert!(icons_shown(&manager) > 0);
    assert!(manager.global::<Theme>().get_site_icons());
}

#[test]
fn typing_requests_nothing_until_the_list_settles() {
    let (_h, manager, icons) = open();
    elapse(SETTLE);
    let before = icons.requested().len();
    type_into(&manager, "Search vault", "a");
    elapse(Duration::from_millis(50));
    type_into(&manager, "Search vault", "am");
    elapse(Duration::from_millis(50));
    assert_eq!(icons.requested().len(), before);
    elapse(SETTLE);
    let after = icons.requested();
    assert!(
        after.len() > before,
        "the new rows on screen load once settled"
    );
    assert!(
        after[before..]
            .iter()
            .all(|host| !after[..before].contains(host)),
        "loaded hosts are not fetched again"
    );
}

#[test]
fn switching_icons_off_hides_them_and_stops_requests() {
    let (h, manager, icons) = open();
    elapse(SETTLE);
    h.app.open_settings();
    let settings = h.app.settings_window().expect("settings");
    click(&settings, "Show site icons");
    assert!(
        !manager.global::<Theme>().get_site_icons(),
        "rows show kind chips"
    );
    assert!(
        !h.settings
            .saved
            .lock()
            .expect("settings")
            .as_ref()
            .expect("saved")
            .show_site_icons
    );
    let before = icons.requested().len();
    type_into(&manager, "Search vault", "git");
    elapse(SETTLE);
    assert_eq!(icons.requested().len(), before, "no requests while off");
    assert_eq!(icons_shown(&manager), 0, "loaded icons are dropped");

    click(&settings, "Show site icons");
    assert!(manager.global::<Theme>().get_site_icons());
    assert!(
        icons.requested().len() > before,
        "back on: the rows on screen load again"
    );
}

#[test]
fn nothing_is_requested_while_the_setting_is_off() {
    let settings = Settings {
        show_site_icons: false,
        ..Settings::default()
    };
    let (h, manager, icons) = open_with(settings, FakeIcons::default());
    elapse(SETTLE);
    type_into(&manager, "Search vault", "git");
    elapse(SETTLE);
    h.app.toggle_quick_panel();
    elapse(SETTLE);
    assert_eq!(icons.requested(), Vec::<String>::new());
    assert!(!manager.global::<Theme>().get_site_icons());
}

#[test]
fn the_quick_panel_loads_its_rows_icons() {
    let (h, _manager, icons) = open();
    elapse(SETTLE);
    h.app.toggle_quick_panel();
    let panel = h.app.quick_panel().expect("quick panel");
    type_into(&panel, "Quick search", "git");
    elapse(SETTLE);
    let rows = panel.get_rows();
    let shown = (0..rows.row_count())
        .filter_map(|row| rows.row_data(row))
        .filter(|row| row.icon.size().width > 0)
        .count();
    assert!(shown > 0, "requested {:?}", icons.requested());
}

#[test]
fn hosts_that_were_unavailable_are_asked_again_at_the_next_settle() {
    let offline = FakeIcons::default();
    offline.offline.store(true, Ordering::SeqCst);
    let (_h, manager, icons) = open_with(Settings::default(), offline);
    elapse(SETTLE);
    let first = icons.requested();
    assert_ne!(first, Vec::<String>::new());
    assert_eq!(icons_shown(&manager), 0, "offline: kind chips");

    icons.offline.store(false, Ordering::SeqCst);
    manager.invoke_visible_range_changed();
    elapse(SETTLE);
    let again = icons.requested();
    assert!(
        first.iter().all(|host| again[first.len()..].contains(host)),
        "every unavailable host is retried: {again:?}"
    );
    assert!(icons_shown(&manager) > 0);
}

fn open_picker(h: &common::Harness, query: &str, host: &str) -> vaultkeeper::ui::BrowserPicker {
    let matches = h
        .vault
        .search(query, &Filter::default())
        .expect("search")
        .iter()
        .filter(|item| item.kind == ItemKind::Login)
        .map(ItemSummaryDto::from)
        .collect();
    let (reply, _answer) = oneshot::channel();
    h.app.request_browser_prompt(BrowserPromptRequest {
        prompt: BrowserPrompt::Fill {
            browser: "Firefox".into(),
            host: host.into(),
            insecure: false,
            matches,
            touch_id: false,
            return_to: None,
        },
        reply,
    });
    h.app.browser_picker().expect("picker")
}

fn picker_icons(picker: &vaultkeeper::ui::BrowserPicker) -> usize {
    let rows = picker.get_rows();
    (0..rows.row_count())
        .filter_map(|row| rows.row_data(row))
        .filter(|row| row.icon.size().width > 0)
        .count()
}

#[test]
fn the_fill_picker_shows_its_logins_icons() {
    let (h, _manager, icons) = open();
    let picker = open_picker(&h, "github", "github.com");
    assert_eq!(picker_icons(&picker), 0, "login chips until loaded");
    elapse(SETTLE);
    assert!(icons.requested().contains(&"github.com".to_owned()));
    assert!(
        picker_icons(&picker) > 0,
        "requested {:?}",
        icons.requested()
    );

    type_into(&picker, "Search vault", "git");
    elapse(SETTLE);
    assert!(
        picker_icons(&picker) > 0,
        "search results keep loaded icons"
    );
}

#[test]
fn the_fill_picker_requests_nothing_while_icons_are_off() {
    let settings = Settings {
        show_site_icons: false,
        ..Settings::default()
    };
    let (h, _manager, icons) = open_with(settings, FakeIcons::default());
    let picker = open_picker(&h, "github", "github.com");
    elapse(SETTLE);
    assert_eq!(icons.requested(), Vec::<String>::new());
    assert!(!picker.global::<Theme>().get_site_icons(), "login chips");
}
