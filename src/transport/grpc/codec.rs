//! gRPC message codec
//!
//! Encodes and decodes gRPC frames compatible with v2ray format.

use bytes::{BufMut, Bytes, BytesMut};
use std::io;

/// Parse one gRPC message frame (v2ray compatible format) without copying.
///
/// Consumes the gRPC frame from `buf` via `split_to` and returns the payload as
/// a `Bytes` handle that shares the underlying allocation (no memcpy).
/// Also returns the number of bytes consumed (for HTTP/2 flow control).
/// Declared gRPC frame length (bytes after the 5-byte header) if the header
/// has arrived, so callers can reject oversized frames before buffering them.
pub fn declared_frame_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    Some(u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize)
}

/// Message body: `Hunk { bytes data = 1; }` on `/Tun`, or
/// `MultiHunk { repeated bytes data = 1; }` on `/TunMulti` — the same wire
/// encoding, with one or more `0x0A <varint len> <bytes>` fields. All entries
/// are returned as one contiguous payload (the tunnel is a byte stream); a
/// single entry is zero-copy, several are concatenated. A frame with no
/// field at all is a valid empty message and yields an empty payload.
pub fn parse_grpc_message_zerocopy(buf: &mut BytesMut) -> io::Result<Option<(Bytes, usize)>> {
    if buf.len() < 5 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported",
        ));
    }

    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let consumed = 5 + grpc_frame_len;
    if buf.len() < consumed {
        return Ok(None);
    }

    // Walk the protobuf fields inside the frame. The overwhelmingly common
    // layout is exactly one field (Hunk): keep that path allocation-free and
    // only collect ranges once a second field shows up (MultiHunk).
    let mut first: Option<(usize, usize)> = None;
    let mut fields: Vec<(usize, usize)> = Vec::new();
    let mut pos = 5;
    while pos < consumed {
        if buf[pos] != 0x0A {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected protobuf tag: 0x{:02X}, expected 0x0A", buf[pos]),
            ));
        }
        let (len_u64, varint_bytes) = decode_varint(&buf[pos + 1..consumed])?;
        let data_start = pos + 1 + varint_bytes;
        // The varint is attacker-controlled (up to u64::MAX): use checked
        // arithmetic so an absurd length is an error, never a wrapped index that
        // would panic (and abort the process with panic = "abort").
        let data_end = usize::try_from(len_u64)
            .ok()
            .and_then(|len| data_start.checked_add(len))
            .filter(|end| *end <= consumed)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "payload length {} exceeds gRPC frame length {}",
                        len_u64, grpc_frame_len
                    ),
                )
            })?;
        match first {
            None => first = Some((data_start, data_end)),
            Some(f) => {
                if fields.is_empty() {
                    fields.push(f);
                }
                fields.push((data_start, data_end));
            }
        }
        pos = data_end;
    }

    // split_to consumes the frame from buf; freeze + slice yields a zero-copy Bytes
    let frame = buf.split_to(consumed).freeze();
    let payload = if !fields.is_empty() {
        let mut out = BytesMut::with_capacity(fields.iter().map(|(s, e)| e - s).sum());
        for (s, e) in &fields {
            out.extend_from_slice(&frame[*s..*e]);
        }
        out.freeze()
    } else {
        match first {
            Some((s, e)) => frame.slice(s..e),
            None => Bytes::new(),
        }
    };

    Ok(Some((payload, consumed)))
}

/// Encode gRPC message frame (single allocation)
pub fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    let varint_bytes = varint_len(payload.len() as u64);
    let proto_len = 1 + varint_bytes + payload.len(); // tag + varint + payload

    let mut buf = BytesMut::with_capacity(5 + proto_len);
    buf.put_u8(0x00); // not compressed
    buf.put_u32(proto_len as u32); // gRPC frame length
    buf.put_u8(0x0A); // protobuf field 1, wire type 2
    encode_varint(payload.len() as u64, &mut buf);
    buf.extend_from_slice(payload);
    buf
}

fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "incomplete varint",
    ))
}

/// Compute the number of bytes needed to encode a varint
fn varint_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7)
}

fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    /// Regression: a 10-byte varint of u64::MAX used to wrap `data_start +
    /// payload_len` in release builds and panic in `frame.slice`.
    #[test]
    fn zerocopy_rejects_overflowing_payload_length() {
        use super::parse_grpc_message_zerocopy;
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0, 0, 0, 16, 0x0A]);
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        buf.extend_from_slice(&[0u8; 8]);
        let err = parse_grpc_message_zerocopy(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // a length that fits usize but exceeds the frame is still rejected
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0, 0, 0, 4, 0x0A, 0x7F, 0, 0]);
        assert!(parse_grpc_message_zerocopy(&mut buf).is_err());
    }

    use super::*;

    #[test]
    fn test_encode_grpc_message_simple() {
        let payload = b"hello";
        let encoded = encode_grpc_message(payload);

        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[5], 0x0A);
    }

    #[test]
    fn test_encode_grpc_message_empty() {
        let payload = b"";
        let encoded = encode_grpc_message(payload);

        assert_eq!(encoded[0], 0x00);
        let frame_len = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
        assert_eq!(frame_len, 2);
    }

    #[test]
    fn test_parse_grpc_message_simple() {
        let payload = b"test data";
        let encoded = encode_grpc_message(payload);

        let mut buf = BytesMut::from(&encoded[..]);
        let result = parse_grpc_message_zerocopy(&mut buf).unwrap();

        assert!(result.is_some());
        let (parsed_payload, consumed) = result.unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(&parsed_payload[..], payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_parse_grpc_message_incomplete_header() {
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        let result = parse_grpc_message_zerocopy(&mut buf).unwrap();
        assert!(result.is_none());
    }

    /// `MultiHunk` (path /TunMulti) packs several `data` fields into one
    /// frame; they form one contiguous byte-stream payload.
    #[test]
    fn multi_hunk_fields_are_concatenated() {
        let mut body = BytesMut::new();
        for part in [&b"ab"[..], b"", b"cde"] {
            body.extend_from_slice(&[0x0A]);
            encode_varint(part.len() as u64, &mut body);
            body.extend_from_slice(part);
        }
        let mut frame = BytesMut::new();
        frame.extend_from_slice(&[0x00]);
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        let total = frame.len();
        let (payload, consumed) = parse_grpc_message_zerocopy(&mut frame).unwrap().unwrap();
        assert_eq!(&payload[..], b"abcde");
        assert_eq!(consumed, total);
        assert!(frame.is_empty());
    }

    /// A zero-length frame is a valid empty Hunk (proto3 omits empty fields).
    #[test]
    fn empty_frame_is_an_empty_message_not_a_stall() {
        let mut buf = BytesMut::from(&[0x00, 0, 0, 0, 0][..]);
        let (payload, consumed) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();
        assert!(payload.is_empty());
        assert_eq!(consumed, 5);
        // followed by a normal frame: the next parse must see it correctly
        let mut buf = BytesMut::from(&[0x00, 0, 0, 0, 0][..]);
        buf.extend_from_slice(&encode_grpc_message(b"next"));
        let (p1, _) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();
        assert!(p1.is_empty());
        let (p2, _) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();
        assert_eq!(&p2[..], b"next");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let encoded = encode_grpc_message(original);
        let mut buf = BytesMut::from(&encoded[..]);

        let (decoded, consumed) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(&decoded[..], &original[..]);
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0);

        buf.clear();
        encode_varint(127, &mut buf);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 127);

        buf.clear();
        encode_varint(128, &mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x01);
    }

    #[test]
    fn test_varint_decoding() {
        let (val, bytes) = decode_varint(&[0]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(bytes, 1);

        let (val, bytes) = decode_varint(&[127]).unwrap();
        assert_eq!(val, 127);
        assert_eq!(bytes, 1);

        let (val, bytes) = decode_varint(&[0x80, 0x01]).unwrap();
        assert_eq!(val, 128);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn test_parse_grpc_message_zerocopy_roundtrip() {
        let payload = b"zero-copy test data";
        let encoded = encode_grpc_message(payload);

        let mut buf = BytesMut::from(&encoded[..]);
        let (parsed_payload, consumed) = parse_grpc_message_zerocopy(&mut buf).unwrap().unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(&parsed_payload[..], &payload[..]);
        // buf should be empty after split_to consumed the frame
        assert!(buf.is_empty());
    }

    #[test]
    fn test_parse_grpc_message_zerocopy_incomplete() {
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        assert!(parse_grpc_message_zerocopy(&mut buf).unwrap().is_none());
        // buf should be unchanged since nothing was consumed
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1000000] {
            let mut buf = BytesMut::new();
            encode_varint(value, &mut buf);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value, "Roundtrip failed for {}", value);
        }
    }
}
