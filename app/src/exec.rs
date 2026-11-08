//! Runs vault work off the UI thread and hands the result back to it.

use std::future::Future;

use tokio::runtime::Handle;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Work runs on the tokio runtime; the continuation runs on the Slint event loop.
    EventLoop,
    /// Work is driven to completion on the calling thread and the continuation runs right after.
    /// For headless tests, where no Slint event loop is running.
    Blocking,
}

#[derive(Clone)]
pub struct Exec {
    handle: Handle,
    mode: Mode,
}

impl Exec {
    #[must_use]
    pub const fn event_loop(handle: Handle) -> Self {
        Self {
            handle,
            mode: Mode::EventLoop,
        }
    }

    /// The handle must belong to a multi-thread runtime so its timers run while blocked on.
    #[must_use]
    pub const fn blocking(handle: Handle) -> Self {
        Self {
            handle,
            mode: Mode::Blocking,
        }
    }

    /// Runs `work` on the runtime, then `then(output)` on the UI thread.
    ///
    /// The continuation runs via `slint::spawn_local` awaiting the tokio `JoinHandle`, so it can
    /// hold `Rc` state; `invoke_from_event_loop` would require it to be `Send`.
    pub fn spawn<T, W, C>(&self, work: W, then: C)
    where
        T: Send + 'static,
        W: Future<Output = T> + Send + 'static,
        C: FnOnce(T) + 'static,
    {
        match self.mode {
            Mode::Blocking => then(self.handle.block_on(work)),
            Mode::EventLoop => {
                let task = self.handle.spawn(work);
                let spawned = slint::spawn_local(async move {
                    match task.await {
                        Ok(output) => then(output),
                        Err(error) => tracing::error!(%error, "background task failed"),
                    }
                });
                if let Err(error) = spawned {
                    tracing::error!(%error, "cannot schedule UI continuation");
                }
            }
        }
    }

    /// Like [`Exec::spawn`] for blocking OS calls such as the Touch ID prompt.
    pub fn spawn_blocking<T, W, C>(&self, work: W, then: C)
    where
        T: Send + 'static,
        W: FnOnce() -> T + Send + 'static,
        C: FnOnce(T) + 'static,
    {
        match self.mode {
            Mode::Blocking => then(work()),
            Mode::EventLoop => {
                let task = self.handle.spawn_blocking(work);
                let spawned = slint::spawn_local(async move {
                    match task.await {
                        Ok(output) => then(output),
                        Err(error) => tracing::error!(%error, "blocking task failed"),
                    }
                });
                if let Err(error) = spawned {
                    tracing::error!(%error, "cannot schedule UI continuation");
                }
            }
        }
    }

    /// Fire-and-forget background work, such as a sync after a write.
    pub fn detach<W>(&self, work: W)
    where
        W: Future<Output = ()> + Send + 'static,
    {
        match self.mode {
            Mode::Blocking => self.handle.block_on(work),
            Mode::EventLoop => drop(self.handle.spawn(work)),
        }
    }

    /// The runtime handle, for wiring streams such as `VaultService::changes`.
    #[must_use]
    pub const fn handle(&self) -> &Handle {
        &self.handle
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use super::*;

    #[test]
    fn blocking_mode_runs_continuation_inline() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let exec = Exec::blocking(runtime.handle().clone());
        let seen = Rc::new(Cell::new(0));
        let sink = Rc::clone(&seen);
        exec.spawn(
            async {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                41 + 1
            },
            move |value| sink.set(value),
        );
        assert_eq!(seen.get(), 42);
        let sink = Rc::clone(&seen);
        exec.spawn_blocking(|| 7, move |value| sink.set(value));
        assert_eq!(seen.get(), 7);
    }
}
