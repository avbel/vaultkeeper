//! A local stand-in for Vaultwarden's `/notifications/hub`: a plain WebSocket server that speaks
//! enough SignalR to exercise the client, with frames built the way Vaultwarden's `serialize` does.

// The upgrade callback's signature is fixed by tungstenite, and Vaultwarden's own VarInt
// encoder masks to 7 bits before narrowing.
#![allow(clippy::result_large_err, clippy::cast_possible_truncation)]

use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use futures_util::{SinkExt, StreamExt};
use rmpv::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        http,
    },
};
use url::Url;

pub type Socket = WebSocketStream<tokio::net::TcpStream>;

#[derive(Debug, Clone)]
pub struct Accepted {
    pub at: Instant,
    pub uri: String,
    /// The `Authorization` header of the upgrade request, if any.
    pub authorization: Option<String>,
}

impl Accepted {
    /// The bearer token the client presented.
    pub fn bearer(&self) -> Option<&str> {
        self.authorization.as_deref()?.strip_prefix("Bearer ")
    }
}

pub struct Hub {
    pub addr: SocketAddr,
    pub accepted: Arc<Mutex<Vec<Accepted>>>,
    task: JoinHandle<()>,
}

impl Hub {
    pub fn base(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    pub fn accepted(&self) -> Vec<Accepted> {
        self.accepted.lock().unwrap().clone()
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a hub whose connections are handled by `handler(connection_index, socket)`. A `reject`
/// answer of `Some(status)` refuses the upgrade with that HTTP status instead.
pub async fn spawn_rejecting<R, H, Fut>(reject: R, handler: H) -> Hub
where
    R: Fn(usize, &Accepted) -> Option<u16> + Send + Sync + 'static,
    H: Fn(usize, Socket) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&accepted);
    let reject = Arc::new(reject);
    let handler = Arc::new(handler);

    let task = tokio::spawn(async move {
        let mut index = 0_usize;
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (log, reject, handler) =
                (Arc::clone(&log), Arc::clone(&reject), Arc::clone(&handler));
            let connection = index;
            index += 1;
            tokio::spawn(async move {
                let callback =
                    |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
                        let seen = Accepted {
                            at: Instant::now(),
                            uri: request.uri().to_string(),
                            authorization: request
                                .headers()
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned),
                        };
                        log.lock().unwrap().push(seen.clone());
                        match reject(connection, &seen) {
                            Some(status) => {
                                Err(http::Response::builder().status(status).body(None).unwrap())
                            }
                            None => Ok(response),
                        }
                    };
                if let Ok(socket) = accept_hdr_async(stream, callback).await {
                    handler(connection, socket).await;
                }
            });
        }
    });
    Hub {
        addr,
        accepted,
        task,
    }
}

pub async fn spawn<H, Fut>(handler: H) -> Hub
where
    H: Fn(usize, Socket) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_rejecting(|_, _| None, handler).await
}

/// Reads the client's handshake request and answers it like Vaultwarden: a binary `{}\x1e`.
pub async fn complete_handshake(socket: &mut Socket) {
    let Some(Ok(Message::Text(request))) = socket.next().await else {
        panic!("client did not open with a text handshake");
    };
    assert_eq!(
        request.as_str(),
        "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}"
    );
    socket
        .send(Message::binary(vec![0x7b, 0x7d, 0x1e]))
        .await
        .unwrap();
}

/// Reads and discards frames until the client goes away; ends once the socket closes.
pub async fn drain(socket: &mut Socket) {
    while let Some(Ok(_)) = socket.next().await {}
}

/// `VarInt(len) ++ payload`, the algorithm of Vaultwarden's `serialize` in `notifications.rs`.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut size = payload.len();
    let mut out = Vec::new();
    loop {
        let mut part = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            part |= 0x80;
        }
        out.push(part);
        if size == 0 {
            break;
        }
    }
    out.extend_from_slice(payload);
    out
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).unwrap();
    frame(&bytes)
}

/// A `ReceiveMessage` invocation shaped like Vaultwarden's `create_update` for a cipher.
pub fn invocation(kind: u8, id: &str, context: Option<&str>) -> Vec<u8> {
    let revision_date = Value::Ext(-1, 1_700_000_000_i64.to_be_bytes().to_vec());
    let payload = Value::Map(vec![
        ("Id".into(), id.into()),
        ("UserId".into(), "user-1".into()),
        ("OrganizationId".into(), Value::Nil),
        ("CollectionIds".into(), Value::Nil),
        ("RevisionDate".into(), revision_date),
    ]);
    let argument = Value::Map(vec![
        ("ContextId".into(), context.map_or(Value::Nil, Value::from)),
        ("Type".into(), i64::from(kind).into()),
        ("Payload".into(), payload),
    ]);
    encode(&Value::Array(vec![
        1.into(),
        Value::Map(vec![]),
        Value::Nil,
        "ReceiveMessage".into(),
        Value::Array(vec![argument]),
    ]))
}

/// SignalR close message `[7, error, allowReconnect]`.
pub fn close_message(error: &str) -> Vec<u8> {
    encode(&Value::Array(vec![7.into(), error.into(), false.into()]))
}
