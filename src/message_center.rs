//! Bounded decoder for the message center's compact WLAN topic records.
//! Only call this after authenticating and decrypting the enclosing payload.

pub const CLIPBOARD_TOPIC: u8 = 2;
pub const MAX_INLINE_TEXT: usize = 3072;
const MAX_PACKET: usize = 131_072;

#[derive(Debug, PartialEq, Eq)]
pub struct Topic<'a> {
    pub id: u8,
    pub sequence: u8,
    pub base: &'a [u8],
    pub extension: &'a [u8],
}

impl<'a> Topic<'a> {
    /// Single inline text item only. Long text and rich content require a separate channel.
    pub fn short_text(&self) -> Option<&'a str> {
        if self.id != CLIPBOARD_TOPIC
            || self.base.len() != 2
            || self.base[0] & 1 != 0
            || self.base[1] != 236
        {
            return None;
        }
        std::str::from_utf8(self.extension).ok()
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    let part = input.get(..length)?;
    *input = &input[length..];
    Some(part)
}

/// Decode static topic IDs. Extended topic definitions (254/255) are not yet supported.
/// Reject truncated records instead of treating missing content as an empty clipboard.
pub fn decode(packet: &[u8]) -> Option<Vec<Topic<'_>>> {
    if packet.len() > MAX_PACKET {
        return None;
    }
    let mut input = packet;
    let _packet_flags = *take(&mut input, 1)?.first()?;
    if input.is_empty() {
        return None;
    }
    let mut topics = Vec::new();
    while !input.is_empty() {
        if topics.len() == 256 {
            return None;
        }
        let header = take(&mut input, 2)?;
        let id = header[0];
        if id >= 254 {
            return None;
        }
        let base = take(&mut input, usize::from(header[1] >> 4))?;
        let low = take(&mut input, 1)?[0];
        let length = if low & 0x80 == 0 {
            usize::from(low)
        } else {
            let high = take(&mut input, 1)?[0];
            // This format uses at most two seven-bit groups.
            if high & 0x80 != 0 {
                return None;
            }
            usize::from(low & 0x7f) | (usize::from(high) << 7)
        };
        let extension = take(&mut input, length)?;
        topics.push(Topic {
            id,
            sequence: header[1] & 15,
            base,
            extension,
        });
    }
    Some(topics)
}

pub fn topic_name(id: u8) -> &'static str {
    match id {
        1 => "power",
        CLIPBOARD_TOPIC => "universalClipboard",
        3 => "relay",
        4 => "handoff",
        5 => "notify",
        _ => "unknown",
    }
}

pub enum ClipboardEvent<'a> {
    Text(&'a str),
    Unsupported,
}

pub fn clipboard_event(payload: &[u8]) -> Option<ClipboardEvent<'_>> {
    use crate::wire;
    if payload.first() != Some(&1) {
        return None;
    }
    let networking = &payload[1..];
    if !wire::fields(networking)?.contains(&wire::Field::Integer(1, 4)) {
        return None;
    }
    let message = wire::bytes_field(networking, 8)?;
    let packet = wire::bytes_field(message, 1)?;
    let topics = decode(packet)?;
    let topic = topics.into_iter().rev().find(|t| t.id == CLIPBOARD_TOPIC)?;
    Some(match topic.short_text() {
        Some(text) => ClipboardEvent::Text(text),
        None => ClipboardEvent::Unsupported,
    })
}

pub fn payload_text(payload: &[u8]) -> Option<&str> {
    match clipboard_event(payload)? {
        ClipboardEvent::Text(text) => Some(text),
        ClipboardEvent::Unsupported => None,
    }
}

/// Encode one inline UTF-8 text item, including its networking module envelope.
pub fn text_payload(text: &str, sequence: u8) -> Option<Vec<u8>> {
    use crate::wire::{integer, message};
    if text.is_empty() || text.len() > MAX_INLINE_TEXT {
        return None;
    }
    let mut packet = vec![
        0,
        CLIPBOARD_TOPIC,
        0x20 | (sequence & 15),
        (sequence & 127) << 1,
        236,
    ];
    let length = text.len();
    if length < 128 {
        packet.push(length as u8);
    } else {
        packet.push((length as u8 & 127) | 128);
        packet.push((length >> 7) as u8);
    }
    packet.extend(text.as_bytes());
    let mut payload = vec![1];
    payload.extend(integer(1, 4));
    payload.extend(message(8, &message(1, &packet)));
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_envelope_handles_utf8_lengths_and_rejects_long_content() {
        for text in [
            "测试 Rust".to_owned(),
            "x".repeat(127),
            "y".repeat(128),
            "z".repeat(MAX_INLINE_TEXT),
        ] {
            assert_eq!(
                payload_text(&text_payload(&text, 127).unwrap()),
                Some(text.as_str())
            );
        }
        assert!(text_payload("", 0).is_none());
        assert!(text_payload(&"x".repeat(MAX_INLINE_TEXT + 1), 0).is_none());
        assert!(payload_text(&[0, 8, 4]).is_none());
    }

    #[test]
    fn relay_is_not_clipboard() {
        let topics = decode(&[0, 3, 0x49, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(topics[0].id, 3);
        assert_ne!(topics[0].id, CLIPBOARD_TOPIC);
        assert_eq!(topics[0].sequence, 9);
        assert_eq!(topics[0].base.len(), 4);
        assert!(topics[0].extension.is_empty());
    }

    #[test]
    fn multiple_topics_and_two_byte_length() {
        let mut packet = vec![0, 1, 0, 0, 2, 0x21, 0, 236, 0x80, 1];
        packet.extend([b'x'; 128]);
        let topics = decode(&packet).unwrap();
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[1].id, CLIPBOARD_TOPIC);
        assert_eq!(topics[1].base, &[0, 236]);
        assert_eq!(topics[1].extension.len(), 128);
    }

    #[test]
    fn truncation_cannot_become_empty_clipboard() {
        let packet = [0, 2, 0x20, 0, 236, 3, b'a', b'b', b'c'];
        for end in 0..packet.len() {
            assert!(decode(&packet[..end]).is_none(), "prefix {end}");
        }
        assert!(decode(&packet).is_some());
        assert!(decode(&[0, 2, 0, 0x80, 0x80]).is_none());
        assert!(decode(&[0, 255, 0, 0]).is_none());
        assert!(decode(&vec![0; MAX_PACKET + 1]).is_none());
    }

    #[test]
    fn unsupported_clipboard_content_is_distinct_from_malformed_or_unrelated_packets() {
        use crate::wire::{integer, message};
        for (id, flags, mime, expected) in
            [(2, 0, 237, true), (2, 1, 236, true), (3, 0, 237, false)]
        {
            let packet = [0, id, 0x20, flags, mime, 1, 42];
            let mut payload = vec![1];
            payload.extend(integer(1, 4));
            payload.extend(message(8, &message(1, &packet)));
            assert_eq!(
                matches!(clipboard_event(&payload), Some(ClipboardEvent::Unsupported)),
                expected
            );
            assert!(payload_text(&payload).is_none());
            payload.pop();
            assert!(clipboard_event(&payload).is_none());
        }
    }

    #[test]
    fn short_text_requires_clipboard_topic_inline_flag_and_text_mime() {
        let text = "测试 Rust".as_bytes();
        let topic = Topic {
            id: 2,
            sequence: 0,
            base: &[8, 236],
            extension: text,
        };
        assert_eq!(topic.short_text(), Some("测试 Rust"));
        assert!(Topic { id: 3, ..topic }.short_text().is_none());
        assert!(
            Topic {
                base: &[9, 236],
                ..topic
            }
            .short_text()
            .is_none()
        );
        assert!(
            Topic {
                base: &[8, 237],
                ..topic
            }
            .short_text()
            .is_none()
        );
        assert!(
            Topic {
                extension: &[255],
                ..topic
            }
            .short_text()
            .is_none()
        );
    }
}
