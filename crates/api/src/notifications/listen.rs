use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    net::TcpStream,
    sync::mpsc::Sender,
    time::{Instant, MissedTickBehavior, interval_at, sleep, timeout},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        Bytes, Message,
        client::IntoClientRequest,
        http::{HeaderValue, Request, header::AUTHORIZATION},
        protocol::WebSocketConfig,
    },
};
use url::Url;
use zeroize::Zeroizing;

use super::{
    ListenError, ListenOptions, Notification,
    frame::{self, Incoming, PING_MESSAGE},
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const MAX_WS_MESSAGE_BYTES: usize = 1 << 20;
/// `UpdateType::LogOut`: never suppressed, even when this device caused it.
const LOG_OUT: u8 = 11;

/// [`listen_with`] using the default timings.
pub async fn listen(
    base: &Url,
    access_token: &str,
    tx: Sender<Notification>,
) -> Result<(), ListenError> {
    listen_with(base, access_token, &tx, &ListenOptions::default()).await
}

/// Connects to `wss://<base>/notifications/hub` (`ws://` for an `http` base) with the token in an
/// `Authorization: Bearer` header, so it never appears in a URL that proxies log, performs the SignalR handshake, sends [`Notification::Connected`] and then forwards
/// notifications until the connection ends.
///
/// Returns `Ok(())` only when the receiving half of `tx` was dropped; every other end of the
/// connection is an error the caller answers by reconnecting (see `run_with_reconnect`).
/// Dropping the returned future closes the socket.
pub async fn listen_with(
    base: &Url,
    access_token: &str,
    tx: &Sender<Notification>,
    options: &ListenOptions,
) -> Result<(), ListenError> {
    session(base, access_token, tx, options, &mut None).await
}

/// `connected_at` is set once the handshake completed, so the reconnect loop can tell a
/// healthy connection from one that died right away.
pub(super) async fn session(
    base: &Url,
    access_token: &str,
    tx: &Sender<Notification>,
    options: &ListenOptions,
    connected_at: &mut Option<Instant>,
) -> Result<(), ListenError> {
    let request = hub_request(base, access_token)?;
    let (mut socket, leftover) = timeout(options.handshake_timeout, connect(request))
        .await
        .map_err(|_| ListenError::HandshakeTimeout(options.handshake_timeout))??;
    *connected_at = Some(Instant::now());

    if tx.send(Notification::Connected).await.is_err() {
        return Ok(());
    }
    if let Flow::Stop = dispatch(&leftover, tx, options).await? {
        return Ok(());
    }
    run(&mut socket, tx, options).await
}

fn hub_request(base: &Url, access_token: &str) -> Result<Request<()>, ListenError> {
    let scheme = match base.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => return Err(ListenError::UnsupportedScheme(other.to_owned())),
    };
    let mut url = base.clone();
    url.set_scheme(scheme)
        .map_err(|()| ListenError::UnsupportedScheme(scheme.to_owned()))?;
    url.path_segments_mut()
        .map_err(|()| ListenError::Url(url::ParseError::RelativeUrlWithCannotBeABaseBase))?
        .pop_if_empty()
        .extend(["notifications", "hub"]);
    url.set_query(None);
    url.set_fragment(None);

    let mut request = url.as_str().into_client_request()?;
    let bearer = Zeroizing::new(format!("Bearer {access_token}"));
    // A token the header syntax cannot carry could never have been issued by the server.
    let mut value = HeaderValue::from_str(&bearer).map_err(|_| ListenError::Unauthorized)?;
    value.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, value);
    Ok(request)
}

/// Opens the socket and completes the SignalR handshake. Returns any hub messages the server
/// packed into the same frame as its handshake reply.
async fn connect(request: Request<()>) -> Result<(Socket, Vec<u8>), ListenError> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_MESSAGE_BYTES));
    let connector = if request.uri().scheme_str() == Some("wss") {
        Some(tls_connector()?)
    } else {
        None
    };
    let (mut socket, _response) =
        connect_async_tls_with_config(request, Some(config), false, connector).await?;

    socket.send(Message::text(frame::HANDSHAKE_REQUEST)).await?;
    loop {
        let reply = match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                frame::parse_handshake_reply(text.as_bytes()).map(<[u8]>::to_vec)
            }
            Some(Ok(Message::Binary(data))) => {
                frame::parse_handshake_reply(&data).map(<[u8]>::to_vec)
            }
            Some(Ok(Message::Close(_))) | None => return Err(ListenError::Closed),
            Some(Ok(_)) => continue,
            Some(Err(error)) => return Err(error.into()),
        };
        let leftover = reply.map_err(|error| ListenError::Handshake(error.to_string()))?;
        return Ok((socket, leftover));
    }
}

/// Certificates are checked by the same platform verifier reqwest uses for HTTPS, so a private
/// CA trusted in the OS store works for live sync exactly when it works for the REST calls.
fn tls_connector() -> Result<Connector, ListenError> {
    let config = ClientConfig::with_platform_verifier()
        .map_err(|error| ListenError::Tls(error.to_string()))?;
    Ok(Connector::Rustls(Arc::new(config)))
}

enum Flow {
    Continue,
    Stop,
}

async fn run(
    socket: &mut Socket,
    tx: &Sender<Notification>,
    options: &ListenOptions,
) -> Result<(), ListenError> {
    let mut ping = interval_at(
        Instant::now() + options.ping_interval,
        options.ping_interval,
    );
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let stale = sleep(options.stale_after);
    tokio::pin!(stale);

    loop {
        tokio::select! {
            incoming = socket.next() => {
                stale.as_mut().reset(Instant::now() + options.stale_after);
                let message = incoming.ok_or(ListenError::Closed)??;
                if let Flow::Stop = handle(message, tx, options).await? {
                    return Ok(());
                }
            }
            _ = ping.tick() => send_pings(socket, options.stale_after).await?,
            () = &mut stale => return Err(ListenError::Stale(options.stale_after)),
            () = tx.closed() => return Ok(()),
        }
    }
}

async fn handle(
    message: Message,
    tx: &Sender<Notification>,
    options: &ListenOptions,
) -> Result<Flow, ListenError> {
    match message {
        Message::Binary(data) => dispatch(&data, tx, options).await,
        Message::Close(_) => Err(ListenError::Closed),
        // tungstenite answers pings itself; any frame already proved the peer is alive.
        Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
            Ok(Flow::Continue)
        }
    }
}

async fn dispatch(
    data: &[u8],
    tx: &Sender<Notification>,
    options: &ListenOptions,
) -> Result<Flow, ListenError> {
    let messages = frame::decode(data).map_err(|error| ListenError::Protocol(error.to_string()))?;
    for message in messages {
        match message {
            Incoming::Ping | Incoming::Ignored => {}
            Incoming::Close(error) => return Err(ListenError::ServerClose(error)),
            Incoming::Update(update) => {
                if is_own_change(&update, options) {
                    continue;
                }
                let notification = Notification::from_update(update.kind, update.id);
                if tx.send(notification).await.is_err() {
                    return Ok(Flow::Stop);
                }
            }
        }
    }
    Ok(Flow::Continue)
}

fn is_own_change(update: &frame::Update, options: &ListenOptions) -> bool {
    update.kind != LOG_OUT
        && options.own_device_id.is_some()
        && update.context_id == options.own_device_id
}

/// A blocked write means the peer stopped reading, which is the same failure as silence.
async fn send_pings(socket: &mut Socket, limit: Duration) -> Result<(), ListenError> {
    let pings = async {
        socket
            .feed(Message::binary(Bytes::from_static(&PING_MESSAGE)))
            .await?;
        socket.send(Message::Ping(Bytes::new())).await
    };
    timeout(limit, pings)
        .await
        .map_err(|_| ListenError::Stale(limit))??;
    Ok(())
}
