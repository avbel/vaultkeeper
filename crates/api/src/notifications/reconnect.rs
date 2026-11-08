use std::time::Duration;

use tokio::{
    sync::mpsc::Sender,
    time::{Instant, sleep},
};
use url::Url;
use zeroize::Zeroizing;

use super::{ListenOptions, Notification, listen::session};

#[derive(Debug, Clone)]
pub struct ReconnectOptions {
    pub listen: ListenOptions,
    /// Wait before the first reconnect; doubles after each failed attempt.
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// A connection that lasted at least this long after its handshake resets the backoff.
    pub healthy_after: Duration,
}

impl Default for ReconnectOptions {
    fn default() -> Self {
        Self {
            listen: ListenOptions::default(),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            healthy_after: Duration::from_secs(60),
        }
    }
}

/// Keeps a notification connection alive: 1 s, 2 s, 4 s ... capped at 60 s between attempts,
/// back to 1 s after a connection that stayed healthy for over 60 s.
///
/// `access_token` is called before every attempt, so a token that expired while the socket was
/// down (they live two hours) can be refreshed there; returning `None` ends the loop. Every
/// successful (re)connect sends [`Notification::Connected`]; treat it as "run a full sync".
///
/// Finishes when the receiver is dropped or the token provider gives up. Dropping the future
/// cancels it, closing the socket and stopping all retries.
pub async fn run_with_reconnect<F, Fut>(
    base: &Url,
    mut access_token: F,
    tx: Sender<Notification>,
    options: &ReconnectOptions,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<Zeroizing<String>>>,
{
    let mut backoff = options.backoff_initial;
    loop {
        let Some(token) = access_token().await else {
            return;
        };
        let mut connected_at = None;
        let outcome = session(base, &token, &tx, &options.listen, &mut connected_at).await;
        drop(token);

        match outcome {
            Ok(()) => return,
            Err(error) => tracing::debug!(%error, "notification connection ended"),
        }
        if connected_at.is_some_and(|at: Instant| at.elapsed() >= options.healthy_after) {
            backoff = options.backoff_initial;
        }
        sleep(backoff).await;
        backoff = next_backoff(backoff, options.backoff_max);
    }
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_up_to_the_cap() {
        let max = Duration::from_secs(60);
        let mut current = Duration::from_secs(1);
        let mut seen = Vec::new();
        for _ in 0..8 {
            seen.push(current.as_secs());
            current = next_backoff(current, max);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60]);
    }

    #[test]
    fn default_options_match_the_documented_schedule() {
        let options = ReconnectOptions::default();
        assert_eq!(options.backoff_initial, Duration::from_secs(1));
        assert_eq!(options.backoff_max, Duration::from_secs(60));
        assert_eq!(options.healthy_after, Duration::from_secs(60));
    }
}
