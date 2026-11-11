use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vk_ipc::browser::BROWSER_MAX_FRAME;
use zeroize::Zeroizing;

// Not cancel-safe: cancellation mid-frame requires closing the input.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut header = [0; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let len = u32::from_ne_bytes(header) as usize;
    if len > BROWSER_MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native message too large",
        ));
    }
    let mut body = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

// Not cancel-safe: cancellation mid-frame requires closing the output.
pub async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= BROWSER_MAX_FRAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "native message too large"))?;
    writer.write_all(&len.to_ne_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

/// Writes a message that may carry a credential with no copy of it: `std::fs::File` is
/// unbuffered, unlike tokio's stdout, which would keep the bytes in a buffer we cannot wipe.
/// The browser reads stdout continuously, so the short blocking write is acceptable.
pub fn write_message_unbuffered<W: io::Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= BROWSER_MAX_FRAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "native message too large"))?;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbuffered_frames_match_the_async_framing() {
        let mut out = Vec::new();
        write_message_unbuffered(&mut out, b"hello").expect("write");
        assert_eq!(out, [&5_u32.to_ne_bytes()[..], b"hello"].concat());
        assert!(write_message_unbuffered(&mut out, &vec![0; BROWSER_MAX_FRAME + 1]).is_err());
    }

    #[tokio::test]
    async fn native_frames_round_trip_and_reject_bad_lengths() {
        let (mut writer, mut reader) = tokio::io::duplex(100);
        write_message(&mut writer, b"hello").await.expect("write");
        assert_eq!(
            read_message(&mut reader)
                .await
                .expect("read")
                .expect("frame")
                .as_slice(),
            b"hello"
        );
        writer
            .write_all(&(u32::try_from(BROWSER_MAX_FRAME + 1).expect("fits")).to_ne_bytes())
            .await
            .expect("header");
        assert_eq!(
            read_message(&mut reader)
                .await
                .expect_err("oversized")
                .kind(),
            io::ErrorKind::InvalidData
        );
        let (mut writer, mut reader) = tokio::io::duplex(100);
        writer
            .write_all(&10_u32.to_ne_bytes())
            .await
            .expect("header");
        writer.write_all(b"short").await.expect("body");
        drop(writer);
        assert_eq!(
            read_message(&mut reader)
                .await
                .expect_err("truncated")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
