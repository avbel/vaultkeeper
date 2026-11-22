//! SSH agent client connection and connection handler

use std::{future::Future, pin::pin, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::{
    auth_policy::{AuthPolicy, AuthRequest, ConnectionContext, SessionBindContext, SignRequest},
    peer_info::PeerInfo,
    protocol::{
        build_identities_answer, build_sign_response, detect_namespace, failure, frame,
        parse_message, read_ssh_string, success, AgentMessage, SignFlags, EXTENSION,
    },
    session_bind::SessionBindState,
    KeyStore,
};
use crate::crypto::{PublicKey, SignablePrivateKey};

// Guards against oversized allocations from untrusted length prefixes on the socket.
const MAX_MESSAGE_LEN: usize = 256 * 1024;
const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";

/// vk patch: how long a connection may sit between requests. Long-lived clients keep an agent
/// connection open across a whole session, so this only reclaims ones that are truly abandoned.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// vk patch: once the first byte of a request arrived, the rest must follow within this time.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// vk patch: the public key algorithm whose sign requests need explicit SHA-2 flags.
const RSA_KEY_ALG: &str = "ssh-rsa";

/// An accepted connection from an SSH agent client, bundling the I/O stream
/// with information about the connecting peer.
pub(crate) struct Connection<S> {
    /// The I/O stream for this connection
    pub(crate) stream: S,
    /// Information about the connected peer process, if available
    pub(crate) peer_info: Option<PeerInfo>,
}

/// Handles an individual SSH agent client connection
pub(crate) struct ConnectionHandler<K, A, S> {
    keystore: Arc<K>,
    auth_policy: Arc<A>,
    connection: Connection<S>,
    token: CancellationToken,
}

impl<K, A, S> ConnectionHandler<K, A, S>
where
    K: KeyStore,
    A: AuthPolicy,
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new connection handler
    pub fn new(
        keystore: Arc<K>,
        auth_policy: Arc<A>,
        connection: Connection<S>,
        token: CancellationToken,
    ) -> Self {
        Self {
            keystore,
            auth_policy,
            connection,
            token,
        }
    }

    /// Handle incoming SSH agent protocol messages from the client.
    ///
    /// Reads length-prefixed SSH agent protocol frames in a loop, dispatches each
    /// message to the appropriate handler, and writes the framed response back.
    /// Exits on cancellation, EOF, a read deadline, or unrecoverable I/O error.
    pub async fn handle(self) {
        let Self {
            keystore,
            auth_policy,
            connection,
            token,
        } = self;
        let peer_info = connection.peer_info;
        debug!(?peer_info, "handler starting");

        // vk patch: buffered so a pending request can watch for the client closing without
        // consuming the bytes of a pipelined next request.
        let mut stream = BufReader::new(connection.stream);
        let mut session_bind_state = SessionBindState::default();

        while let Some(msg) = read_frame(&mut stream, &token).await {
            if msg.is_empty() {
                debug!("handler skipping empty message");
                continue;
            }

            // Pass Arc clones rather than &self to avoid requiring S: Sync
            let response = if msg.first() == Some(&EXTENSION) {
                handle_extension_message(&msg[1..], &mut session_bind_state)
            } else {
                let pending = handle_message(
                    &msg,
                    peer_info.as_ref(),
                    &session_bind_state,
                    &keystore,
                    &auth_policy,
                );
                let Some(response) = respond_unless_gone(pending, &mut stream, &token).await else {
                    break;
                };
                response
            };

            if let Err(error) = stream.write_all(&frame(response)).await {
                error!(%error, "Failed to write response, closing connection");
                break;
            }
        }

        debug!("handler finished");
    }
}

/// vk patch: reads one length-prefixed request. Returns `None` when the caller should close the
/// connection: cancelled, closed, an I/O error, an oversized length, or a missed deadline.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    token: &CancellationToken,
) -> Option<Vec<u8>> {
    debug!("handler waiting for a request");
    let started = tokio::select! {
        () = token.cancelled() => {
            debug!("handler received cancellation signal");
            return None;
        }
        result = timeout(IDLE_TIMEOUT, stream.fill_buf()) => match result {
            Ok(Ok(buffered)) => !buffered.is_empty(),
            Ok(Err(error)) => {
                error!(%error, "I/O error on connection");
                false
            }
            Err(_) => {
                info!("Closing an idle connection");
                false
            }
        },
    };
    if !started {
        trace!("Connection closed");
        return None;
    }

    tokio::select! {
        () = token.cancelled() => {
            debug!("handler received cancellation signal");
            None
        }
        result = timeout(MESSAGE_TIMEOUT, read_message(stream)) => result.unwrap_or_else(|_| {
            warn!("Client stalled in the middle of a request, closing connection");
            None
        }),
    }
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    debug!("handler reading length");
    read_exact_or_log(stream, &mut len_buf).await?;

    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > MAX_MESSAGE_LEN {
        warn!(
            msg_len,
            "Message length exceeds maximum, closing connection"
        );
        return None;
    }
    let mut msg = vec![0u8; msg_len];

    debug!("handler reading message");
    read_exact_or_log(stream, &mut msg).await?;
    Some(msg)
}

async fn read_exact_or_log<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    buf: &mut [u8],
) -> Option<()> {
    match stream.read_exact(buf).await {
        Ok(_) => Some(()),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            trace!("Connection closed");
            None
        }
        Err(error) => {
            error!(%error, "I/O error on connection");
            None
        }
    }
}

/// vk patch: waits for a response that may block on the user's approval, giving up when the
/// server stops or the client goes away so no prompt outlives its client. Data arriving instead
/// of EOF is a pipelined request; it stays buffered for the next read and the watch ends.
async fn respond_unless_gone<S, F>(
    response: F,
    stream: &mut BufReader<S>,
    token: &CancellationToken,
) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
    F: Future<Output = Vec<u8>>,
{
    let mut response = pin!(response);
    let mut watching = true;
    loop {
        tokio::select! {
            response = &mut response => return Some(response),
            () = token.cancelled() => {
                debug!("handler received cancellation signal while a request was pending");
                return None;
            }
            closed = client_closed(stream), if watching => {
                if closed {
                    info!("Client went away while its request was pending, dropping it");
                    return None;
                }
                watching = false;
            }
        }
    }
}

async fn client_closed<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> bool {
    match stream.fill_buf().await {
        Ok(buffered) => buffered.is_empty(),
        Err(error) => {
            debug!(%error, "I/O error while a request was pending");
            true
        }
    }
}

fn handle_extension_message(payload: &[u8], session_bind_state: &mut SessionBindState) -> Vec<u8> {
    let Some((name, rest)) = read_ssh_string(payload) else {
        return failure();
    };
    match name {
        SESSION_BIND_EXTENSION => handle_session_bind(rest, session_bind_state),
        _ => {
            warn!(
                name = std::str::from_utf8(name).unwrap_or("<non-utf8>"),
                "Received unsupported extension"
            );
            failure()
        }
    }
}

fn handle_session_bind(payload: &[u8], session_bind_state: &mut SessionBindState) -> Vec<u8> {
    if session_bind_state.parse_and_verify(payload) {
        success()
    } else {
        warn!("session-bind verification failed");
        failure()
    }
}

async fn handle_message<K: KeyStore, A: AuthPolicy>(
    msg: &[u8],
    peer_info: Option<&PeerInfo>,
    session_bind_state: &SessionBindState,
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
) -> Vec<u8> {
    let Some(message) = parse_message(msg) else {
        error!("Received malformed message");
        return failure();
    };

    match message {
        AgentMessage::RequestIdentities => handle_list_request(keystore, auth_policy).await,
        AgentMessage::SignRequest {
            public_key,
            data,
            flags,
        } => {
            handle_sign_request(
                public_key,
                data,
                flags,
                peer_info,
                session_bind_state,
                keystore,
                auth_policy,
            )
            .await
        }
        AgentMessage::Unknown(msg_type) => {
            debug!(msg_type, "Received unhandled message type");
            failure()
        }
    }
}

async fn handle_list_request<K: KeyStore, A: AuthPolicy>(
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
) -> Vec<u8> {
    debug!("handling list request");

    let Ok(authorized) = auth_policy
        .authorize(&AuthRequest::List)
        .await
        .inspect_err(|error| error!(%error, "Authorization error for list request"))
    else {
        return failure();
    };

    if !authorized {
        info!("List request denied.");
        return failure();
    }

    match keystore.get_all_public_keys_and_names() {
        Ok(keys) => build_identities_answer(keys),
        Err(error) => {
            error!(%error, "Failed to retrieve keys from keystore");
            failure()
        }
    }
}

async fn handle_sign_request<K: KeyStore, A: AuthPolicy>(
    public_key: PublicKey,
    data: Vec<u8>,
    flags: Option<SignFlags>,
    peer_info: Option<&PeerInfo>,
    session_bind_state: &SessionBindState,
    keystore: &Arc<K>,
    auth_policy: &Arc<A>,
) -> Vec<u8> {
    debug!("handling sign request");

    if public_key.alg() == RSA_KEY_ALG && flags.is_none() {
        warn!("Refusing an RSA sign request without SHA-2 flags; SHA-1 is not permitted");
        return failure();
    }

    let sign_request = SignRequest {
        public_key: public_key.clone(),
        namespace: detect_namespace(&data),
        connection: ConnectionContext {
            process_name: peer_info.map(|p| p.process_name().to_string()),
            session_bind: if session_bind_state.host_fingerprint.is_empty() {
                None
            } else {
                Some(SessionBindContext {
                    is_forwarding: session_bind_state.is_forwarding,
                    host_fingerprint: session_bind_state.host_fingerprint.clone(),
                })
            },
        },
    };

    let Ok(authorized) = auth_policy
        .authorize(&AuthRequest::Sign(sign_request))
        .await
        .inspect_err(|error| error!(%error, "Sign request authorization error"))
    else {
        return failure();
    };

    if !authorized {
        debug!("Sign request denied by auth policy");
        return failure();
    }

    let Ok(maybe_key) = keystore
        .get_private_key(&public_key)
        .inspect_err(|error| error!(%error, "Failed to retrieve key from keystore"))
    else {
        return failure();
    };

    let Some(private_key) = maybe_key else {
        warn!("Key not found in keystore");
        return failure();
    };

    let Ok(signing_key) = SignablePrivateKey::try_from((private_key, flags)).inspect_err(
        |error| warn!(%error, ?flags, "Unable to create signable key with provided request input"),
    ) else {
        return failure();
    };

    build_sign_response(&signing_key.sign(&data))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate::eq;

    use crate::{
        authorization::AuthError,
        crypto::{PrivateKey, PublicKey},
        server::{session_bind::SessionBindState, AuthPolicy, AuthRequest},
        storage::keystore::MockKeyStore,
    };
    const FAILURE: u8 = 5;
    const SUCCESS: u8 = 6;
    const REQUEST_IDENTITIES: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;
    const SIGN_REQUEST: u8 = 13;
    const SIGN_RESPONSE: u8 = 14;

    use crate::server::test_common::{
        make_minimal_ed25519_blob, make_session_bind_payload_ed25519, make_sign_request_msg,
        write_ssh_string, AlwaysAllowPolicy,
    };

    fn make_minimal_rsa_blob() -> Vec<u8> {
        let alg = b"ssh-rsa";
        let mut blob = Vec::new();
        blob.extend_from_slice(&(alg.len() as u32).to_be_bytes());
        blob.extend_from_slice(alg);
        blob
    }

    // Builds the slice that handle_extension_message receives: [string name][raw payload]
    fn make_extension_payload(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_ssh_string(&mut payload, name);
        payload.extend_from_slice(data);
        payload
    }

    struct ErrorAuthPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for ErrorAuthPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            Err(AuthError::KeyNotFound)
        }
    }

    struct AlwaysDenyPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for AlwaysDenyPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            Ok(false)
        }
    }

    struct CapturingAuthPolicy {
        captured: std::sync::Mutex<Option<AuthRequest>>,
    }

    #[async_trait::async_trait]
    impl AuthPolicy for CapturingAuthPolicy {
        async fn authorize(&self, req: &AuthRequest) -> Result<bool, AuthError> {
            *self.captured.lock().unwrap() = Some(req.clone());
            Ok(true)
        }
    }

    #[tokio::test]
    async fn unknown_message_type_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[99u8],
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn list_request_when_authorized_returns_identities_answer() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_all_public_keys_and_names()
            .once()
            .returning(|| {
                Ok(vec![(
                    PublicKey {
                        alg: "ssh-ed25519".to_string(),
                        blob: vec![1, 2, 3],
                    },
                    "Test Key".to_string(),
                )])
            });
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response[0], IDENTITIES_ANSWER);
        assert_eq!(u32::from_be_bytes(response[1..5].try_into().unwrap()), 1);
    }

    #[tokio::test]
    async fn list_request_when_denied_returns_failure() {
        let keystore = MockKeyStore::new();
        let auth_policy = Arc::new(AlwaysDenyPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn list_request_when_keystore_errors_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_all_public_keys_and_names()
            .once()
            .returning(|| Err(anyhow::anyhow!("keystore error")));
        let auth_policy = Arc::new(AlwaysAllowPolicy);

        let response = super::handle_message(
            &[REQUEST_IDENTITIES],
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_authorized_key_found_returns_sign_response() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let blob = make_minimal_ed25519_blob();
        let expected_public_key = PublicKey {
            alg: "ssh-ed25519".to_string(),
            blob: blob.clone(),
        };

        let private_key = PrivateKey::Ed25519(keypair);
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .with(eq(expected_public_key))
            .once()
            .return_once(move |_| Ok(Some(private_key)));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response[0], SIGN_RESPONSE);
    }

    #[tokio::test]
    async fn sign_request_when_auth_denied_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysDenyPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_auth_error_returns_failure() {
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(ErrorAuthPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &keystore,
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_key_not_found_in_keystore_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_when_keystore_error_returns_failure() {
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Err(anyhow::anyhow!("keystore error")));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
    }

    #[tokio::test]
    async fn sign_request_rsa_without_flags_returns_failure() {
        // vk patch: the request is refused before the user is asked, so neither the policy nor
        // the keystore is reached.
        let blob = make_minimal_rsa_blob();
        let mut keystore = MockKeyStore::new();
        keystore.expect_get_private_key().never();

        let auth_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });
        let msg = make_sign_request_msg(&blob, b"test data", 0); // no flags → would imply SHA-1

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response, vec![FAILURE]);
        assert!(
            auth_policy.captured.lock().unwrap().is_none(),
            "a SHA-1 RSA request must not reach the approval prompt"
        );
    }

    #[tokio::test]
    async fn sign_request_rsa_sha256_flag_produces_sha256_signature() {
        use ssh_key::{private::RsaKeypair, rand_core::OsRng};

        // SSH_AGENT_RSA_SHA2_256 flag
        const RSA_SHA2_256: u32 = 2;

        const MIN_RSA_BITS: usize = 2048;

        let keypair = RsaKeypair::random(&mut OsRng, MIN_RSA_BITS).unwrap();
        let blob = make_minimal_rsa_blob();
        let expected_public_key = PublicKey {
            alg: "ssh-rsa".to_string(),
            blob: blob.clone(),
        };

        let private_key = PrivateKey::Rsa(keypair);
        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .with(eq(expected_public_key))
            .once()
            .return_once(move |_| Ok(Some(private_key)));

        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let msg = make_sign_request_msg(&blob, b"test data", RSA_SHA2_256);

        let response = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &auth_policy,
        )
        .await;

        assert_eq!(response[0], SIGN_RESPONSE);
        let alg_len = u32::from_be_bytes(response[5..9].try_into().unwrap()) as usize;
        let alg_str = std::str::from_utf8(&response[9..9 + alg_len]).unwrap();
        assert_eq!(alg_str, "rsa-sha2-256");
    }

    #[test]
    fn extension_truncated_name_returns_failure() {
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&[0u8, 1u8, 2u8], &mut state);
        assert_eq!(response, vec![FAILURE]);
    }

    #[test]
    fn extension_unknown_name_returns_failure() {
        let payload = make_extension_payload(b"query", &[]);
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![FAILURE]);
    }

    #[test]
    fn session_bind_invalid_payload_returns_failure() {
        let payload = make_extension_payload(b"session-bind@openssh.com", &[0xDE, 0xAD]);
        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![FAILURE]);
        assert!(!state.is_forwarding);
        assert!(state.host_fingerprint.is_empty());
    }

    #[test]
    fn session_bind_valid_not_forwarding_returns_success() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], false);
        let payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![SUCCESS]);
        assert!(!state.is_forwarding);
    }

    #[test]
    fn session_bind_valid_forwarding_returns_success_and_sets_flag() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let response = super::handle_extension_message(&payload, &mut state);
        assert_eq!(response, vec![SUCCESS]);
        assert!(state.is_forwarding);
    }

    #[test]
    fn session_bind_is_forwarding_latched_on_rebind() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let mut state = SessionBindState::default();

        let forwarding_payload = make_session_bind_payload_ed25519(&keypair, &[0x01u8; 32], true);
        let ext1 = make_extension_payload(b"session-bind@openssh.com", &forwarding_payload);
        let r1 = super::handle_extension_message(&ext1, &mut state);
        assert_eq!(r1, vec![SUCCESS]);
        assert!(
            state.is_forwarding,
            "first bind (forwarding=true) should set flag"
        );

        let not_forwarding_payload =
            make_session_bind_payload_ed25519(&keypair, &[0x02u8; 32], false);
        let ext2 = make_extension_payload(b"session-bind@openssh.com", &not_forwarding_payload);
        let r2 = super::handle_extension_message(&ext2, &mut state);
        assert_eq!(r2, vec![SUCCESS]);
        assert!(
            state.is_forwarding,
            "latch must not be cleared by a non-forwarding rebind"
        );
    }

    #[tokio::test]
    async fn session_bind_is_forwarding_propagates_to_sign_request_auth() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let ext_payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        let bind_response = super::handle_extension_message(&ext_payload, &mut state);
        assert_eq!(bind_response, vec![SUCCESS]);
        assert!(state.is_forwarding);

        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ =
            super::handle_message(&msg, None, &state, &Arc::new(keystore), &capturing_policy).await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert!(
                sign_req
                    .connection
                    .session_bind
                    .as_ref()
                    .is_some_and(|s| s.is_forwarding),
                "is_forwarding must propagate to auth"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn host_fingerprint_propagates_to_sign_request_auth() {
        use ssh_key::{private::Ed25519Keypair, rand_core::OsRng};

        let keypair = Ed25519Keypair::random(&mut OsRng);
        let bind_payload = make_session_bind_payload_ed25519(&keypair, &[0x42u8; 32], true);
        let ext_payload = make_extension_payload(b"session-bind@openssh.com", &bind_payload);

        let mut state = SessionBindState::default();
        super::handle_extension_message(&ext_payload, &mut state);
        let expected_fingerprint = state.host_fingerprint.clone();
        assert!(!expected_fingerprint.is_empty());

        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ =
            super::handle_message(&msg, None, &state, &Arc::new(keystore), &capturing_policy).await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert_eq!(
                sign_req
                    .connection
                    .session_bind
                    .as_ref()
                    .map(|s| s.host_fingerprint.as_str()),
                Some(expected_fingerprint.as_str()),
                "host_fingerprint must propagate to auth request"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn sign_request_without_session_bind_has_no_host_fingerprint() {
        let blob = make_minimal_ed25519_blob();
        let msg = make_sign_request_msg(&blob, b"test data", 0);

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_private_key()
            .once()
            .returning(|_| Ok(None));

        let capturing_policy = Arc::new(CapturingAuthPolicy {
            captured: std::sync::Mutex::new(None),
        });

        let _ = super::handle_message(
            &msg,
            None,
            &SessionBindState::default(),
            &Arc::new(keystore),
            &capturing_policy,
        )
        .await;

        let captured = capturing_policy.captured.lock().unwrap();
        if let Some(AuthRequest::Sign(sign_req)) = captured.as_ref() {
            assert!(
                sign_req.connection.session_bind.is_none(),
                "session_bind must be None when no session-bind was received"
            );
        } else {
            panic!("expected Sign auth request to be captured");
        }
    }

    #[tokio::test]
    async fn oversized_message_length_closes_connection_without_panic() {
        use tokio::io::{duplex, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        let (mut client, server) = duplex(1024);
        let keystore = Arc::new(MockKeyStore::new());
        let auth_policy = Arc::new(AlwaysAllowPolicy);
        let token = CancellationToken::new();

        let handler = super::ConnectionHandler::new(
            keystore,
            auth_policy,
            super::Connection {
                stream: server,
                peer_info: None,
            },
            token,
        );

        // Send a length one byte over the 256 KiB cap
        let oversized_len = (256 * 1024 + 1) as u32;
        client
            .write_all(&oversized_len.to_be_bytes())
            .await
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), handler.handle())
            .await
            .expect("handler should exit, denying oversized message length");
    }

    // vk patch: tests for the read deadlines and the pending-request close watch.

    struct PendingForeverPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for PendingForeverPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            std::future::pending().await
        }
    }

    struct SlowAllowPolicy;

    #[async_trait::async_trait]
    impl AuthPolicy for SlowAllowPolicy {
        async fn authorize(&self, _: &AuthRequest) -> Result<bool, AuthError> {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok(true)
        }
    }

    fn handler_over<A: AuthPolicy>(
        keystore: MockKeyStore,
        auth_policy: A,
        server: tokio::io::DuplexStream,
    ) -> super::ConnectionHandler<MockKeyStore, A, tokio::io::DuplexStream> {
        super::ConnectionHandler::new(
            Arc::new(keystore),
            Arc::new(auth_policy),
            super::Connection {
                stream: server,
                peer_info: None,
            },
            tokio_util::sync::CancellationToken::new(),
        )
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        frame
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_closed_after_the_idle_timeout() {
        let (_client, server) = tokio::io::duplex(1024);
        let handler = handler_over(MockKeyStore::new(), AlwaysAllowPolicy, server);

        tokio::time::timeout(
            super::IDLE_TIMEOUT + std::time::Duration::from_secs(1),
            handler.handle(),
        )
        .await
        .expect("an idle connection is closed");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_request_is_closed_after_the_message_timeout() {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tokio::io::duplex(1024);
        let handler = handler_over(MockKeyStore::new(), AlwaysAllowPolicy, server);
        client.write_all(&[0, 0]).await.unwrap();

        tokio::time::timeout(
            super::MESSAGE_TIMEOUT + std::time::Duration::from_secs(1),
            handler.handle(),
        )
        .await
        .expect("a half-sent request is dropped long before the idle timeout");
    }

    #[tokio::test]
    async fn client_closing_while_approval_is_pending_drops_the_request() {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tokio::io::duplex(1024);
        let handler = handler_over(MockKeyStore::new(), PendingForeverPolicy, server);
        let msg = make_sign_request_msg(&make_minimal_ed25519_blob(), b"data", 0);
        client.write_all(&framed(&msg)).await.unwrap();
        drop(client);

        tokio::time::timeout(std::time::Duration::from_secs(1), handler.handle())
            .await
            .expect("the handler stops waiting for approval once the client is gone");
    }

    #[tokio::test]
    async fn pipelined_request_is_not_mistaken_for_a_close() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut keystore = MockKeyStore::new();
        keystore
            .expect_get_all_public_keys_and_names()
            .times(2)
            .returning(|| Ok(vec![]));
        let (mut client, server) = tokio::io::duplex(1024);
        let handler = handler_over(keystore, SlowAllowPolicy, server);
        let task = tokio::spawn(handler.handle());

        let two_requests = [framed(&[REQUEST_IDENTITIES]), framed(&[REQUEST_IDENTITIES])].concat();
        client.write_all(&two_requests).await.unwrap();
        let mut answers = [0u8; 18];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut answers),
        )
        .await
        .expect("both requests are answered")
        .unwrap();
        drop(client);

        assert_eq!(answers[4], IDENTITIES_ANSWER);
        assert_eq!(answers[13], IDENTITIES_ANSWER);
        task.await.unwrap();
    }
}
