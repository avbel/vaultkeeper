//! Measures the blocking round-trip the Slint UI thread pays for `search`.
//! Run with `--nocapture` to see the numbers; `--release` for production figures.

mod common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bwl_vault::{VaultService, model::Filter};
use common::{Daemon, FakeVault, unlocked};

const ITEMS: usize = 400;
const CALLS: usize = 1000;

struct Percentiles {
    p50: Duration,
    p99: Duration,
}

fn measure(vault: &Arc<bwl_ipc::RemoteVault>, query: &str, expected_rows: usize) -> Percentiles {
    let filter = Filter::default();
    let mut samples: Vec<Duration> = (0..CALLS)
        .map(|_| {
            let started = Instant::now();
            let rows = vault.search(query, &filter).expect("search");
            let elapsed = started.elapsed();
            assert_eq!(rows.len(), expected_rows);
            elapsed
        })
        .collect();
    samples.sort_unstable();
    Percentiles {
        p50: samples[CALLS / 2],
        p99: samples[CALLS * 99 / 100],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::print_stderr, reason = "the measurement is this test's output")]
async fn search_round_trip_latency_over_400_items() {
    let daemon = Daemon::start(FakeVault::new(unlocked(), ITEMS)).await;
    let (vault, _events) = daemon.connect().await;
    let vault = Arc::new(vault);
    // Called from a plain thread, as the Slint UI thread would.
    let (one_row, all_rows) = std::thread::spawn(move || {
        measure(&vault, "item 123", 1);
        (measure(&vault, "item 123", 1), measure(&vault, "", ITEMS))
    })
    .join()
    .expect("measuring thread");
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    eprintln!(
        "search over IPC ({build}, {CALLS} calls, {ITEMS} items): \
         1 row p50 {:?} p99 {:?}; {ITEMS} rows p50 {:?} p99 {:?}",
        one_row.p50, one_row.p99, all_rows.p50, all_rows.p99
    );
    // Generous bound for slow CI machines and debug builds; the docs quote the measured values.
    assert!(
        all_rows.p99 < Duration::from_millis(50),
        "{:?}",
        all_rows.p99
    );
}
