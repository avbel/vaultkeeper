//! Tasks that run while a session is unlocked and the machine is awake: the sync worker (30-min
//! timer + debounced triggers), the notifications websocket and, while offline, the probe.
//! Each is a `JoinHandle` owned by [`Tasks`] and aborted on lock, switch, log out, sleep and drop.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{self, Instant, MissedTickBehavior},
};
use url::Url;
use vk_api::{
    Prober,
    notifications::{Notification, run_with_reconnect},
};
use zeroize::Zeroizing;

use super::{Inner, lock};
use crate::Error;

const NOTIFICATION_BUFFER: usize = 32;
/// A steady stream of triggers still syncs at least this many debounce windows apart.
const DEBOUNCE_MAX_WINDOWS: u32 = 8;

#[derive(Default)]
pub(crate) struct Tasks {
    worker: Option<JoinHandle<()>>,
    websocket: Option<JoinHandle<()>>,
    probe: Option<JoinHandle<()>>,
}

impl Tasks {
    fn take_all(&mut self) -> Vec<JoinHandle<()>> {
        [self.worker.take(), self.websocket.take(), self.probe.take()]
            .into_iter()
            .flatten()
            .inspect(JoinHandle::abort)
            .collect()
    }
}

fn running(handle: Option<&JoinHandle<()>>) -> bool {
    handle.is_some_and(|handle| !handle.is_finished())
}

/// Which background tasks are alive, for status displays and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackgroundStatus {
    pub sync_worker: bool,
    pub websocket: bool,
    /// The websocket completed a handshake since it (re)started and has not been seen failing.
    pub websocket_connected: bool,
    pub offline_probe: bool,
}

impl Inner {
    pub(crate) fn background_status(&self) -> BackgroundStatus {
        let tasks = lock(&self.tasks);
        BackgroundStatus {
            sync_worker: running(tasks.worker.as_ref()),
            websocket: running(tasks.websocket.as_ref()),
            websocket_connected: running(tasks.websocket.as_ref())
                && self.websocket_connected.load(Ordering::SeqCst),
            offline_probe: running(tasks.probe.as_ref()),
        }
    }

    /// The server of the unlocked session if `epoch` is still current.
    fn current_server(&self, epoch: u64) -> Option<Url> {
        let state = self.read_state();
        let active = state.active.as_ref()?;
        (state.epoch == epoch && active.unlocked.is_some()).then(|| active.record.server.clone())
    }

    fn current_epoch(&self) -> Option<u64> {
        let state = self.read_state();
        let active = state.active.as_ref()?;
        active.unlocked.as_ref().map(|_| state.epoch)
    }

    pub(crate) fn start_background(self: &Arc<Self>, epoch: u64) {
        let mut tasks = lock(&self.tasks);
        if self.asleep() {
            return;
        }
        let Some(server) = self.current_server(epoch) else {
            return;
        };
        let runtime = &self.config.runtime;
        if !running(tasks.worker.as_ref()) {
            tasks.worker = Some(runtime.spawn(sync_worker(Arc::clone(self), epoch)));
        }
        if !running(tasks.websocket.as_ref()) {
            self.websocket_connected.store(false, Ordering::SeqCst);
            tasks.websocket =
                Some(runtime.spawn(websocket_task(Arc::clone(self), epoch, server.clone())));
        }
        if self.is_offline() && !running(tasks.probe.as_ref()) {
            tasks.probe = Some(runtime.spawn(probe_task(Arc::clone(self), epoch, server, false)));
        }
    }

    /// Aborts every task. Awaiting the returned handles waits until their futures are dropped.
    pub(crate) fn stop_background(&self) -> Vec<JoinHandle<()>> {
        let handles = lock(&self.tasks).take_all();
        self.websocket_connected.store(false, Ordering::SeqCst);
        handles
    }

    /// Starts the offline probe unless it already runs; `immediate` skips its current wait.
    pub(crate) fn ensure_probe(self: &Arc<Self>, epoch: u64, immediate: bool) {
        let mut tasks = lock(&self.tasks);
        if running(tasks.probe.as_ref()) {
            if immediate {
                self.probe_wake.notify_one();
            }
            return;
        }
        if self.asleep() {
            return;
        }
        let Some(server) = self.current_server(epoch) else {
            return;
        };
        tasks.probe = Some(self.config.runtime.spawn(probe_task(
            Arc::clone(self),
            epoch,
            server,
            immediate,
        )));
    }

    fn restart_websocket(self: &Arc<Self>, epoch: u64) {
        let mut tasks = lock(&self.tasks);
        if let Some(old) = tasks.websocket.take() {
            old.abort();
        }
        if self.asleep() {
            return;
        }
        let Some(server) = self.current_server(epoch) else {
            return;
        };
        self.websocket_connected.store(false, Ordering::SeqCst);
        tasks.websocket = Some(self.config.runtime.spawn(websocket_task(
            Arc::clone(self),
            epoch,
            server,
        )));
    }

    pub(crate) fn request_sync(&self) {
        self.sync_wanted.notify_one();
    }

    pub(crate) fn on_sleep(&self) {
        self.asleep.store(true, Ordering::SeqCst);
        drop(self.stop_background());
    }

    pub(crate) fn on_wake(self: &Arc<Self>) {
        self.asleep.store(false, Ordering::SeqCst);
        let Some(epoch) = self.current_epoch() else {
            return;
        };
        self.restart_websocket(epoch);
        self.start_background(epoch);
        self.request_sync();
        if self.is_offline() {
            self.ensure_probe(epoch, true);
        }
    }

    pub(crate) fn on_network_change(self: &Arc<Self>) {
        if !self.is_offline() {
            return;
        }
        if let Some(epoch) = self.current_epoch() {
            self.ensure_probe(epoch, true);
        }
    }

    /// Trailing debounce: returns after `quiet` without a new trigger (or a bounded maximum).
    async fn debounce(&self, quiet: Duration) {
        let deadline = Instant::now() + quiet * DEBOUNCE_MAX_WINDOWS;
        loop {
            tokio::select! {
                () = self.sync_wanted.notified() => {
                    if Instant::now() >= deadline {
                        return;
                    }
                }
                () = time::sleep(quiet) => return,
            }
        }
    }

    /// `rejected` is the token the hub just refused; it is refreshed instead of reused.
    async fn notification_token(
        self: &Arc<Self>,
        epoch: u64,
        rejected: Option<Zeroizing<String>>,
    ) -> Option<Zeroizing<String>> {
        let ctx = self.unlocked_ctx().ok().filter(|ctx| ctx.epoch == epoch)?;
        match self.access_token(&ctx, rejected.as_ref()).await {
            Ok(token) => Some(token),
            Err(Error::Api(vk_api::Error::Unauthorized)) => None,
            Err(error) => {
                tracing::debug!(%error, "no access token for the notifications hub");
                if error.is_offline() {
                    self.went_offline(&ctx);
                }
                // Keep the reconnect loop alive; the attempt fails and backs off.
                Some(Zeroizing::default())
            }
        }
    }

    fn on_notification(self: &Arc<Self>, epoch: u64, notification: &Notification) {
        match notification {
            Notification::Connected => {
                self.websocket_connected.store(true, Ordering::SeqCst);
                self.request_sync();
            }
            Notification::LogOut => {
                tracing::info!("the server revoked this session; locking");
                if self.is_current(epoch) {
                    self.lock_session();
                }
            }
            Notification::Other(_) => {}
            Notification::CipherChanged { .. }
            | Notification::CipherDeleted { .. }
            | Notification::FolderChanged { .. }
            | Notification::FolderDeleted { .. }
            | Notification::VaultChanged => self.request_sync(),
        }
    }

    fn after_recovery(self: &Arc<Self>, epoch: u64) {
        if !self.websocket_connected.load(Ordering::SeqCst) {
            self.restart_websocket(epoch);
        }
    }
}

async fn sync_worker(inner: Arc<Inner>, epoch: u64) {
    let period = inner.config.timings.sync_interval;
    let quiet = inner.config.timings.sync_debounce;
    let mut timer = time::interval_at(Instant::now() + period, period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = inner.sync_wanted.notified() => inner.debounce(quiet).await,
            _ = timer.tick() => {}
        }
        if !inner.is_current(epoch) {
            return;
        }
        if let Err(error) = inner.sync_now(Some(epoch)).await {
            tracing::debug!(%error, "background sync failed");
        }
        timer.reset();
    }
}

async fn websocket_task(inner: Arc<Inner>, epoch: u64, server: Url) {
    let mut options = inner.config.timings.notifications.clone();
    options.listen.own_device_id = Some(inner.config.device.identifier.to_string());
    let (tx, mut rx) = mpsc::channel(NOTIFICATION_BUFFER);
    let tokens = Arc::clone(&inner);
    let token_provider = move |rejected| {
        let inner = Arc::clone(&tokens);
        async move { inner.notification_token(epoch, rejected).await }
    };
    let connection = run_with_reconnect(&server, token_provider, tx, &options);
    tokio::pin!(connection);
    loop {
        tokio::select! {
            () = &mut connection => break,
            Some(notification) = rx.recv() => inner.on_notification(epoch, &notification),
        }
    }
    inner.websocket_connected.store(false, Ordering::SeqCst);
}

/// `GET {base}/alive` with backoff until the server answers, then an immediate full sync.
async fn probe_task(inner: Arc<Inner>, epoch: u64, server: Url, immediate: bool) {
    let timings = &inner.config.timings;
    let prober = match Prober::new(&server, timings.probe_timeout) {
        Ok(prober) => prober,
        Err(error) => {
            tracing::warn!(%error, "could not build the offline probe client");
            return;
        }
    };
    let mut delay = if immediate {
        Duration::ZERO
    } else {
        timings.probe_initial
    };
    loop {
        tokio::select! {
            () = time::sleep(delay) => {}
            () = inner.probe_wake.notified() => {}
        }
        if !inner.is_current(epoch) || !inner.is_offline() {
            return;
        }
        if is_alive(&prober).await {
            match inner.sync_now(Some(epoch)).await {
                Ok(()) => {
                    inner.after_recovery(epoch);
                    return;
                }
                Err(error) if error.is_offline() => {}
                Err(error) => {
                    // The server answered, so this is not offline mode (e.g. the session
                    // expired); writes should report the real error instead.
                    tracing::debug!(%error, "sync after the server came back failed");
                    inner.set_offline(false);
                    return;
                }
            }
        }
        delay = next_probe_delay(delay, timings.probe_initial, timings.probe_max);
    }
}

pub(crate) fn next_probe_delay(current: Duration, initial: Duration, max: Duration) -> Duration {
    if current.is_zero() {
        initial
    } else {
        current.saturating_mul(2).min(max)
    }
}

async fn is_alive(prober: &Prober) -> bool {
    match prober.alive().await {
        // A bad certificate means the server answered: let the sync fail with that error instead
        // of showing "offline" while waiting for a server that is already up.
        Ok(()) | Err(vk_api::Error::Tls(_)) => true,
        Err(error) => {
            tracing::debug!(%error, "offline probe failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_backoff_is_5_10_20_40_then_60() {
        let initial = Duration::from_secs(5);
        let max = Duration::from_secs(60);
        let mut delay = initial;
        let mut seen = vec![delay.as_secs()];
        for _ in 0..5 {
            delay = next_probe_delay(delay, initial, max);
            seen.push(delay.as_secs());
        }
        assert_eq!(seen, [5, 10, 20, 40, 60, 60]);
        assert_eq!(next_probe_delay(Duration::ZERO, initial, max), initial);
    }
}
