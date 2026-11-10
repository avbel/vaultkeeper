//! Secret-bearing DTOs and frames must leave no plaintext in freed heap memory.
//!
//! The global allocator below scans every block it frees for a sentinel while a check is
//! running. A plain `String` holding the sentinel is the control: it must be seen, which proves
//! the detector works. This file has a single test so no other test frees memory meanwhile.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use vk_ipc::{
    dto::{
        CustomFieldDto, IdentityDto, ItemDataDto, ItemDraftDto, LoginRequestDto, SshKeyDto,
        TotpCodeDto,
    },
    frame::{HEADER_LEN, decode, encode},
    protocol::{Call, DaemonMessage, Reply, UiMessage},
};
use zeroize::Zeroizing;

const SENTINEL: &str = "S3NT1NEL-of-the-zeroize-test";

static SCANNING: AtomicBool = AtomicBool::new(false);
static SIGHTINGS: AtomicUsize = AtomicUsize::new(0);

struct ScanningAllocator;

// SAFETY: every method forwards to `System` with the caller's arguments, so `System`'s
// guarantees carry over; the scan only reads a block before handing it back.
unsafe impl GlobalAlloc for ScanningAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Zeroed, so every byte the scan later reads has been written.
        // SAFETY: forwarded unchanged; `layout` has a non-zero size per the trait contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SCANNING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` initialised bytes from `alloc`
            // above; it stays valid until `System.dealloc` below and nobody else uses it now.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block
                .windows(SENTINEL.len())
                .any(|window| window == SENTINEL.as_bytes())
            {
                SIGHTINGS.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: `ptr` and `layout` come from `alloc` above, as the trait contract requires.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ScanningAllocator = ScanningAllocator;

/// Exactly sized, so building it frees no intermediate copy.
fn plain() -> String {
    let mut text = String::with_capacity(SENTINEL.len());
    text.push_str(SENTINEL);
    text
}

fn secret() -> Zeroizing<String> {
    Zeroizing::new(plain())
}

fn freed_copies(work: impl FnOnce()) -> usize {
    SIGHTINGS.store(0, Ordering::SeqCst);
    SCANNING.store(true, Ordering::SeqCst);
    work();
    SCANNING.store(false, Ordering::SeqCst);
    SIGHTINGS.load(Ordering::SeqCst)
}

fn draft() -> ItemDraftDto {
    ItemDraftDto {
        name: plain(),
        notes: secret(),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: vec![CustomFieldDto {
            name: plain(),
            value: secret(),
            hidden: true,
            field_type: 1,
            source_index: None,
            withheld: false,
        }],
        data: ItemDataDto::Login {
            username: plain(),
            password: secret(),
            totp: secret(),
            uris: vec![plain()],
        },
        revision_date: None,
    }
}

fn identity_draft() -> ItemDraftDto {
    let mut identity = IdentityDto::default();
    identity.first_name = plain();
    identity.ssn = secret();
    identity.passport_number = secret();
    let mut draft = draft();
    draft.data = ItemDataDto::Identity(Box::new(identity));
    draft
}

type Check = (&'static str, Box<dyn FnOnce()>);

fn round_trip_daemon(message: &DaemonMessage) {
    let frame = encode(message).expect("encode");
    let decoded: DaemonMessage = decode(&frame[HEADER_LEN..]).expect("decode");
    drop(decoded);
    drop(frame);
}

fn round_trip_ui(message: &UiMessage) {
    let frame = encode(message).expect("encode");
    let decoded: UiMessage = decode(&frame[HEADER_LEN..]).expect("decode");
    drop(decoded);
    drop(frame);
}

#[test]
fn secrets_leave_no_plaintext_in_freed_memory() {
    assert!(
        freed_copies(|| drop(plain())) >= 1,
        "control: a plain String must be detected"
    );
    assert_eq!(freed_copies(|| drop(secret())), 0, "Zeroizing<String>");
    assert_eq!(freed_copies(|| drop(draft())), 0, "login draft DTO");
    assert_eq!(
        freed_copies(|| drop(identity_draft())),
        0,
        "identity draft DTO"
    );
    assert_eq!(
        freed_copies(|| drop(TotpCodeDto {
            code: secret(),
            period: 30,
            remaining: 5,
        })),
        0,
        "TOTP code DTO"
    );
    assert_eq!(
        freed_copies(|| drop(LoginRequestDto {
            server: String::from("https://vault.example.com/"),
            email: String::from("alice@example.com"),
            password: secret(),
        })),
        0,
        "login request DTO"
    );
    assert_eq!(
        freed_copies(|| drop(SshKeyDto {
            cipher_id: "k1".into(),
            name: String::from("deploy"),
            private_key: secret(),
        })),
        0,
        "SSH key DTO"
    );

    let checks: [Check; 5] = [
        (
            "draft reply frame",
            Box::new(|| {
                let message = DaemonMessage::Response {
                    id: 1,
                    result: Ok(Reply::Draft(Box::new(identity_draft()))),
                };
                round_trip_daemon(&message);
            }),
        ),
        (
            "reveal reply frame",
            Box::new(|| {
                let message = DaemonMessage::Response {
                    id: 2,
                    result: Ok(Reply::Secret(secret())),
                };
                round_trip_daemon(&message);
            }),
        ),
        (
            "verify master password request frame",
            Box::new(|| {
                round_trip_ui(&UiMessage::Request {
                    id: 3,
                    call: Call::VerifyMasterPassword(secret()),
                });
            }),
        ),
        (
            "unlock request frame",
            Box::new(|| {
                round_trip_ui(&UiMessage::Request {
                    id: 4,
                    call: Call::UnlockWithPassword(secret()),
                });
            }),
        ),
        (
            "save request frame",
            Box::new(|| {
                round_trip_ui(&UiMessage::Request {
                    id: 5,
                    call: Call::Save {
                        id: None,
                        draft: Box::new(draft()),
                    },
                });
            }),
        ),
    ];
    for (name, check) in checks {
        assert_eq!(freed_copies(check), 0, "{name}");
    }
}
