use std::time::Duration;

use tokio::{
    sync::mpsc::Sender,
    time::{Instant, sleep},
};
use url::Url;
use zeroize::Zeroizing;

use super::{ListenError, ListenOptions, Notification, listen::session};

#[derive(Debug, Clone)]
pub struct ReconnectOptions {
    pub listen: ListenOptions,
    /// Wait before the first reconnect; doubles after each failed attempt.
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// Cap for failures a retry cannot fix by itself (the hub answering 404 or 403, a bad URL, a
    /// refused handshake). Still retried, since a proxy or server can be reconfigured, but each
    /// attempt also fetches a token and may refresh it.
    pub permanent_backoff_max: Duration,
    /// A connection that lasted at least this long after its handshake resets the backoff.
    pub healthy_after: Duration,
}

impl Default for ReconnectOptions {
    fn default() -> Self {
        Self {
            listen: ListenOptions::default(),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            permanent_backoff_max: Duration::from_mins(30),
            healthy_after: Duration::from_secs(60),
        }
    }
}

/// Keeps a notification connection alive: 1 s, 2 s, 4 s ... capped at 60 s between attempts,
/// back to 1 s after a connection that stayed healthy for over 60 s. A failure that will not go
/// away by itself keeps doubling up to `permanent_backoff_max` (30 min) instead.
///
/// `access_token` is called before every attempt, so a token that expired while the socket was
/// down (they live two hours) can be refreshed there; returning `None` ends the loop. Its argument
/// is the token the hub just rejected with HTTP 401, which the provider must not hand out again
/// (refresh it instead), and `None` after any other failure. Every
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
    F: FnMut(Option<Zeroizing<String>>) -> Fut,
    Fut: Future<Output = Option<Zeroizing<String>>>,
{
    let mut backoff = options.backoff_initial;
    let mut rejected = None;
    loop {
        let Some(token) = access_token(rejected.take()).await else {
            return;
        };
        let mut connected_at = None;
        let outcome = session(base, &token, &tx, &options.listen, &mut connected_at).await;

        let error = match outcome {
            Ok(()) => return,
            Err(error) => error,
        };
        match &error {
            ListenError::Unauthorized => rejected = Some(token),
            other => tracing::debug!(error = %other, "notification connection ended"),
        }
        if connected_at.is_some_and(|at: Instant| at.elapsed() >= options.healthy_after) {
            backoff = options.backoff_initial;
        }
        let cap = backoff_cap(&error, options);
        let wait = backoff.min(cap);
        sleep(wait).await;
        backoff = next_backoff(wait, cap);
    }
}

fn backoff_cap(error: &ListenError, options: &ReconnectOptions) -> Duration {
    if is_permanent(error) {
        options.permanent_backoff_max
    } else {
        options.backoff_max
    }
}

/// 408 and 429 are the server asking to come back later, not a refusal.
fn is_permanent(error: &ListenError) -> bool {
    match error {
        ListenError::Status(status) => {
            (400..500).contains(status) && ![REQUEST_TIMEOUT, TOO_MANY_REQUESTS].contains(status)
        }
        ListenError::UnsupportedScheme(_) | ListenError::Url(_) | ListenError::Handshake(_) => true,
        ListenError::Unauthorized
        | ListenError::Tls(_)
        | ListenError::WebSocket(_)
        | ListenError::HandshakeTimeout(_)
        | ListenError::Protocol(_)
        | ListenError::Closed
        | ListenError::ServerClose(_)
        | ListenError::Stale(_) => false,
    }
}

const REQUEST_TIMEOUT: u16 = 408;
const TOO_MANY_REQUESTS: u16 = 429;

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
    fn permanent_failures_back_off_to_the_long_cap_and_others_to_the_short_one() {
        let options = ReconnectOptions::default();
        let long = Duration::from_mins(30);
        for permanent in [
            ListenError::Status(404),
            ListenError::Status(403),
            ListenError::UnsupportedScheme("ftp".into()),
            ListenError::Url(url::ParseError::EmptyHost),
            ListenError::Handshake("refused".into()),
        ] {
            assert_eq!(backoff_cap(&permanent, &options), long, "{permanent}");
        }
        for transient in [
            ListenError::Unauthorized,
            ListenError::Status(408),
            ListenError::Status(429),
            ListenError::Status(502),
            ListenError::Closed,
            ListenError::Stale(Duration::from_secs(35)),
            ListenError::HandshakeTimeout(Duration::from_secs(10)),
        ] {
            assert_eq!(
                backoff_cap(&transient, &options),
                Duration::from_secs(60),
                "{transient}"
            );
        }
    }

    #[test]
    fn default_options_match_the_documented_schedule() {
        let options = ReconnectOptions::default();
        assert_eq!(options.backoff_initial, Duration::from_secs(1));
        assert_eq!(options.backoff_max, Duration::from_secs(60));
        assert_eq!(options.permanent_backoff_max, Duration::from_mins(30));
        assert_eq!(options.healthy_after, Duration::from_secs(60));
    }
}
