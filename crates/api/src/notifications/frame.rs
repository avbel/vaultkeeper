//! SignalR "messagepack" hub protocol, the subset Vaultwarden speaks.
//!
//! Every hub message is `VarInt(len) ++ msgpack`, and a WebSocket frame may carry several of them.
//! The VarInt is the 7-bit little-endian form from `BinaryMessageFormat.js`, at most 5 bytes.

use rmpv::Value;
use thiserror::Error;

pub(crate) const HANDSHAKE_REQUEST: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
/// `[6]`: SignalR keep-alive, already length-prefixed.
pub(crate) const PING_MESSAGE: [u8; 3] = [0x02, 0x91, 0x06];

const RECORD_SEPARATOR: u8 = 0x1e;
const MAX_VARINT_BYTES: usize = 5;
/// Real notifications are a few hundred bytes; anything past this is a desynchronised stream.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

const TYPE_INVOCATION: u64 = 1;
const TYPE_PING: u64 = 6;
const TYPE_CLOSE: u64 = 7;
const RECEIVE_MESSAGE: &str = "ReceiveMessage";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    Ping,
    /// Hub message type 7, with the optional error text.
    Close(Option<String>),
    Update(Update),
    /// Well-formed messages this client has no use for (completions, other targets).
    Ignored,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Update {
    /// Vaultwarden's `UpdateType` number.
    pub(crate) kind: u8,
    /// `Payload.Id`: the cipher or folder uuid.
    pub(crate) id: Option<String>,
    /// `ContextId`: the device that caused the change.
    pub(crate) context_id: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum FrameError {
    #[error("length prefix is longer than {MAX_VARINT_BYTES} bytes")]
    VarIntTooLong,
    #[error("frame ends inside a message")]
    Truncated,
    #[error("message of {0} bytes exceeds the {MAX_MESSAGE_BYTES} byte limit")]
    MessageTooLong(usize),
    #[error("invalid MessagePack: {0}")]
    MessagePack(String),
    #[error("hub message is not an array")]
    NotAnArray,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum HandshakeError {
    #[error("reply has no record separator")]
    MissingSeparator,
    #[error("reply is not JSON: {0}")]
    NotJson(String),
    #[error("server refused the handshake: {0}")]
    Refused(String),
}

/// Validates the handshake reply and returns whatever hub messages followed it in the same frame.
pub(crate) fn parse_handshake_reply(data: &[u8]) -> Result<&[u8], HandshakeError> {
    let end = data
        .iter()
        .position(|byte| *byte == RECORD_SEPARATOR)
        .ok_or(HandshakeError::MissingSeparator)?;
    let reply: serde_json::Value = serde_json::from_slice(&data[..end])
        .map_err(|error| HandshakeError::NotJson(error.to_string()))?;
    match reply.get("error").and_then(serde_json::Value::as_str) {
        Some(message) => Err(HandshakeError::Refused(message.to_owned())),
        None => Ok(&data[end + 1..]),
    }
}

pub(crate) fn decode(mut frame: &[u8]) -> Result<Vec<Incoming>, FrameError> {
    let mut messages = Vec::new();
    while !frame.is_empty() {
        let (length, rest) = read_var_int(frame)?;
        if length > MAX_MESSAGE_BYTES {
            return Err(FrameError::MessageTooLong(length));
        }
        if rest.len() < length {
            return Err(FrameError::Truncated);
        }
        let (message, tail) = rest.split_at(length);
        messages.push(decode_message(message)?);
        frame = tail;
    }
    Ok(messages)
}

fn read_var_int(bytes: &[u8]) -> Result<(usize, &[u8]), FrameError> {
    let mut value = 0_usize;
    for (index, byte) in bytes.iter().take(MAX_VARINT_BYTES).enumerate() {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((value, &bytes[index + 1..]));
        }
    }
    if bytes.len() < MAX_VARINT_BYTES {
        Err(FrameError::Truncated)
    } else {
        Err(FrameError::VarIntTooLong)
    }
}

fn decode_message(mut bytes: &[u8]) -> Result<Incoming, FrameError> {
    let value = rmpv::decode::read_value(&mut bytes)
        .map_err(|error| FrameError::MessagePack(error.to_string()))?;
    let Value::Array(items) = value else {
        return Err(FrameError::NotAnArray);
    };
    Ok(match items.first().and_then(Value::as_u64) {
        Some(TYPE_PING) => Incoming::Ping,
        Some(TYPE_CLOSE) => {
            Incoming::Close(items.get(1).and_then(Value::as_str).map(str::to_owned))
        }
        Some(TYPE_INVOCATION) => {
            decode_invocation(&items).map_or(Incoming::Ignored, Incoming::Update)
        }
        _ => Incoming::Ignored,
    })
}

/// `[1, headers, invocationId, "ReceiveMessage", [{"ContextId", "Type", "Payload": {"Id", ...}}]]`
fn decode_invocation(items: &[Value]) -> Option<Update> {
    if items.get(3)?.as_str()? != RECEIVE_MESSAGE {
        return None;
    }
    let argument = items.get(4)?.as_array()?.first()?.as_map()?;
    let kind = u8::try_from(lookup(argument, "Type")?.as_u64()?).ok()?;
    let id = lookup(argument, "Payload")
        .and_then(Value::as_map)
        .and_then(|payload| lookup(payload, "Id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let context_id = lookup(argument, "ContextId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(Update {
        kind,
        id,
        context_id,
    })
}

fn lookup<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[1, {}, nil, "ReceiveMessage", [{"ContextId": nil, "Type": 0, "Payload": {"Id": "ab"}}]]`
    /// written out by hand from the MessagePack spec (fixarray 0x9N, fixmap 0x8N, fixstr 0xaN, nil 0xc0).
    #[rustfmt::skip]
    const CIPHER_UPDATE: [u8; 54] = [
        0x35, // VarInt(53)
        0x95, 0x01, 0x80, 0xc0, // array(5), 1, {}, nil
        0xae, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, // "ReceiveMessage"
        0x91, 0x83, // array(1), map(3)
        0xa9, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x49, 0x64, 0xc0, // "ContextId": nil
        0xa4, 0x54, 0x79, 0x70, 0x65, 0x00, // "Type": 0
        0xa7, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x81, 0xa2, 0x49, 0x64, 0xa2, 0x61, 0x62, // "Payload": {"Id": "ab"}
    ];

    fn update(kind: u8, id: Option<&str>) -> Incoming {
        Incoming::Update(Update {
            kind,
            id: id.map(str::to_owned),
            context_id: None,
        })
    }

    #[test]
    fn handshake_request_is_the_documented_json_plus_record_separator() {
        assert_eq!(
            HANDSHAKE_REQUEST.as_bytes(),
            b"{\"protocol\":\"messagepack\",\"version\":1}\x1e"
        );
    }

    #[test]
    fn ping_message_is_length_prefixed_array_of_type_six() {
        assert_eq!(PING_MESSAGE, [0x02, 0x91, 0x06]);
        assert_eq!(decode(&PING_MESSAGE), Ok(vec![Incoming::Ping]));
    }

    #[test]
    fn empty_handshake_reply_is_accepted() {
        assert_eq!(parse_handshake_reply(&[0x7b, 0x7d, 0x1e]), Ok(&[][..]));
    }

    #[test]
    fn handshake_reply_returns_trailing_messages() {
        let mut reply = vec![0x7b, 0x7d, 0x1e];
        reply.extend_from_slice(&PING_MESSAGE);
        assert_eq!(parse_handshake_reply(&reply), Ok(&PING_MESSAGE[..]));
    }

    #[test]
    fn handshake_error_reply_is_refused_with_its_message() {
        let reply = b"{\"error\":\"Requested protocol 'x' is not available.\"}\x1e";
        assert_eq!(
            parse_handshake_reply(reply),
            Err(HandshakeError::Refused(
                "Requested protocol 'x' is not available.".into()
            ))
        );
    }

    #[test]
    fn handshake_reply_without_separator_or_json_is_rejected() {
        assert_eq!(
            parse_handshake_reply(b"{}"),
            Err(HandshakeError::MissingSeparator)
        );
        assert!(matches!(
            parse_handshake_reply(b"nope\x1e"),
            Err(HandshakeError::NotJson(_))
        ));
    }

    #[test]
    fn decodes_a_vaultwarden_cipher_update() {
        assert_eq!(decode(&CIPHER_UPDATE), Ok(vec![update(0, Some("ab"))]));
    }

    #[test]
    fn decodes_several_messages_in_one_frame() {
        let mut frame = CIPHER_UPDATE.to_vec();
        frame.extend_from_slice(&PING_MESSAGE);
        frame.extend_from_slice(&CIPHER_UPDATE);
        assert_eq!(
            decode(&frame),
            Ok(vec![
                update(0, Some("ab")),
                Incoming::Ping,
                update(0, Some("ab"))
            ])
        );
    }

    #[test]
    fn multi_byte_length_prefix_is_decoded() {
        // [7, "x" * 150] = 0x92 0x07 0xd9 0x96 + 150 bytes = 154 bytes -> VarInt 0x9a 0x01.
        let mut frame = vec![0x9a, 0x01, 0x92, 0x07, 0xd9, 0x96];
        frame.extend(std::iter::repeat_n(b'x', 150));
        assert_eq!(
            decode(&frame),
            Ok(vec![Incoming::Close(Some("x".repeat(150)))])
        );
    }

    #[test]
    fn close_message_without_error_carries_none() {
        // [7, nil, false]
        assert_eq!(
            decode(&[0x04, 0x93, 0x07, 0xc0, 0xc2]),
            Ok(vec![Incoming::Close(None)])
        );
    }

    #[test]
    fn unrelated_messages_are_ignored() {
        // Completion [3, {}, "id", 0].
        let completion = [0x07, 0x94, 0x03, 0x80, 0xa2, 0x69, 0x64, 0x00];
        assert_eq!(decode(&completion), Ok(vec![Incoming::Ignored]));
        // Invocation of another target: [1, {}, nil, "Other", []].
        let other = [
            0x0b, 0x95, 0x01, 0x80, 0xc0, 0xa5, 0x4f, 0x74, 0x68, 0x65, 0x72, 0x90,
        ];
        assert_eq!(decode(&other), Ok(vec![Incoming::Ignored]));
    }

    #[test]
    fn truncated_frames_are_errors() {
        assert_eq!(decode(&CIPHER_UPDATE[..20]), Err(FrameError::Truncated));
        assert_eq!(decode(&[0x80]), Err(FrameError::Truncated));
    }

    #[test]
    fn overlong_varint_and_oversized_messages_are_errors() {
        assert_eq!(
            decode(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(FrameError::VarIntTooLong)
        );
        // VarInt(65537) = 0x81 0x80 0x04
        assert_eq!(
            decode(&[0x81, 0x80, 0x04]),
            Err(FrameError::MessageTooLong(65537))
        );
    }

    #[test]
    fn non_array_and_corrupt_messagepack_are_errors() {
        assert_eq!(decode(&[0x01, 0x05]), Err(FrameError::NotAnArray));
        assert!(matches!(
            // array(2) announced, one element present
            decode(&[0x02, 0x92, 0x01]),
            Err(FrameError::MessagePack(_))
        ));
    }

    #[test]
    fn empty_frame_has_no_messages() {
        assert_eq!(decode(&[]), Ok(vec![]));
    }
}
