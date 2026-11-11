//! Framing: a u32 little-endian body length, then the postcard body.
//!
//! Frames carry decrypted secrets, so every buffer that holds a body is a fresh, exactly sized
//! `Zeroizing<Vec<u8>>`: it never grows (a growing `Vec` frees its old copy without wiping it)
//! and is wiped when dropped. There is no buffered reader or writer, for the same reason.

use std::io;

use postcard::ser_flavors::Size;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

use crate::IpcError;

/// Largest accepted body. Search results for a few thousand items stay far below this.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
pub const HEADER_LEN: usize = 4;

/// Encodes `message` into one frame (header included).
pub fn encode<T: Serialize + ?Sized>(message: &T) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let len =
        postcard::serialize_with_flavor(message, Size::default()).map_err(IpcError::Encode)?;
    let header = u32::try_from(len)
        .ok()
        .filter(|_| len <= MAX_FRAME_LEN)
        .ok_or(IpcError::FrameTooLarge { len })?;
    let mut frame = Zeroizing::new(vec![0; HEADER_LEN + len]);
    frame[..HEADER_LEN].copy_from_slice(&header.to_le_bytes());
    postcard::to_slice(message, &mut frame[HEADER_LEN..]).map_err(IpcError::Encode)?;
    Ok(frame)
}

/// Reads one frame body; `None` when the peer closed the socket between frames.
///
/// Not cancel-safe: dropping the future mid-frame loses the stream position.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
    read_frame_with_limit(reader, MAX_FRAME_LEN).await
}

/// Reads a frame with a caller-specific size limit, checked before allocation.
///
/// Not cancel-safe: dropping the future mid-frame loses the stream position.
pub async fn read_frame_with_limit<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
    let mut header = [0; HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
    if len > limit.min(MAX_FRAME_LEN) {
        return Err(IpcError::FrameTooLarge { len });
    }
    let mut body = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Decodes a whole body; trailing bytes are a protocol violation.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, IpcError> {
    let (message, rest) = postcard::take_from_bytes(body).map_err(IpcError::Decode)?;
    if rest.is_empty() {
        Ok(message)
    } else {
        Err(IpcError::Protocol("trailing bytes after a message"))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::protocol::UiMessage;

    #[test]
    fn hello_has_the_documented_byte_layout() {
        // Length 2 (LE), then postcard: variant index 0 as varint, version 1 as varint.
        let frame = encode(&UiMessage::Hello {
            protocol_version: 1,
        })
        .expect("encode");
        assert_eq!(frame.as_slice(), &[2, 0, 0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn frames_round_trip_through_a_stream() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let frame = encode(&UiMessage::SshApprovalReply {
            request_id: 300,
            approved: true,
            remember: false,
        })
        .expect("encode");
        client.write_all(&frame).await.expect("write");
        drop(client);
        let body = read_frame(&mut server)
            .await
            .expect("read")
            .expect("one frame");
        let UiMessage::SshApprovalReply {
            request_id,
            approved,
            remember,
        } = decode(&body).expect("decode")
        else {
            panic!("wrong message");
        };
        assert_eq!((request_id, approved, remember), (300, true, false));
        assert!(read_frame(&mut server).await.expect("eof").is_none());
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_before_allocating() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let too_long = u32::try_from(MAX_FRAME_LEN + 1).expect("fits");
        client
            .write_all(&too_long.to_le_bytes())
            .await
            .expect("write");
        let error = read_frame(&mut server).await.expect_err("must fail");
        assert!(
            matches!(error, IpcError::FrameTooLarge { len } if len == MAX_FRAME_LEN + 1),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn frame_of_exactly_the_limit_is_accepted() {
        let (mut client, mut server) = tokio::io::duplex(1024 * 1024);
        let writer = tokio::spawn(async move {
            let len = u32::try_from(MAX_FRAME_LEN).expect("fits");
            client.write_all(&len.to_le_bytes()).await.expect("header");
            client
                .write_all(&vec![0; MAX_FRAME_LEN])
                .await
                .expect("body");
        });
        let body = read_frame(&mut server).await.expect("read").expect("frame");
        assert_eq!(body.len(), MAX_FRAME_LEN);
        writer.await.expect("writer");
    }

    #[test]
    fn encoding_more_than_the_limit_fails() {
        let big = vec![0_u8; MAX_FRAME_LEN];
        let error = encode(&big).expect_err("must fail");
        // A u8 sequence encodes as a 4-byte varint length plus one byte per element.
        assert!(
            matches!(error, IpcError::FrameTooLarge { len } if len == MAX_FRAME_LEN + 4),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn truncated_body_is_an_error_not_a_clean_close() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[10, 0, 0, 0, 1, 2]).await.expect("write");
        drop(client);
        let error = read_frame(&mut server).await.expect_err("must fail");
        assert!(matches!(&error, IpcError::Io(io) if io.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn trailing_bytes_and_garbage_are_rejected() {
        assert!(matches!(
            decode::<UiMessage>(&[0, 1, 9]),
            Err(IpcError::Protocol(_))
        ));
        assert!(matches!(
            decode::<UiMessage>(&[200]),
            Err(IpcError::Decode(_))
        ));
        assert!(matches!(decode::<UiMessage>(&[]), Err(IpcError::Decode(_))));
    }
}
