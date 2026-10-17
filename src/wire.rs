//! Bounded, allocation-light parsing for the initial Lyra device-info exchange.
//! This deliberately does not claim to be a complete KCP implementation.
#[derive(Debug, PartialEq, Eq)]
pub enum Field<'a> {
    Integer(u32, u64),
    Bytes(u32, &'a [u8]),
}
fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 127 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
pub(crate) fn integer(id: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(&mut out, u64::from(id) << 3);
    varint(&mut out, value);
    out
}
pub(crate) fn message(id: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(&mut out, u64::from(id) << 3 | 2);
    varint(&mut out, value.len() as u64);
    out.extend(value);
    out
}
fn read_varint(input: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0;
    for i in 0..10 {
        let byte = *input.get(*pos)?;
        *pos += 1;
        if i == 9 && byte > 1 {
            return None;
        }
        result |= u64::from(byte & 127) << (i * 7);
        if byte & 128 == 0 {
            return Some(result);
        }
    }
    None
}
pub fn fields(input: &[u8]) -> Option<Vec<Field<'_>>> {
    if input.len() > 131072 {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        if out.len() == 1024 {
            return None;
        }
        let key = read_varint(input, &mut pos)?;
        let id = u32::try_from(key >> 3).ok()?;
        if id == 0 || id > 536870911 {
            return None;
        }
        match key & 7 {
            0 => out.push(Field::Integer(id, read_varint(input, &mut pos)?)),
            wire @ (1 | 2 | 5) => {
                let length = match wire {
                    1 => 8,
                    5 => 4,
                    _ => usize::try_from(read_varint(input, &mut pos)?).ok()?,
                };
                let end = pos.checked_add(length)?;
                out.push(Field::Bytes(id, input.get(pos..end)?));
                pos = end;
            }
            _ => return None,
        }
    }
    Some(out)
}
pub(crate) fn bytes_field(input: &[u8], id: u32) -> Option<&[u8]> {
    fields(input)?
        .into_iter()
        .rev()
        .find_map(|field| match field {
            Field::Bytes(n, bytes) if n == id => Some(bytes),
            _ => None,
        })
}
pub fn sync_request(device_id: u32, connection: u32, now_ms: u64) -> Vec<u8> {
    sync_request_with_auth(device_id, connection, now_ms, None)
}
pub(crate) fn sync_request_with_auth(
    device_id: u32,
    connection: u32,
    now_ms: u64,
    auth: Option<&[u8]>,
) -> Vec<u8> {
    let mut info = message(2, format!("{device_id:08X}").as_bytes());
    info.extend(integer(3, 1));
    info.extend(message(4, &device_id.to_be_bytes()));
    info.extend(integer(5, 14));
    info.extend(message(6, crate::networking::DEVICE_NAME.as_bytes()));
    info.extend(message(11, b"macOS standalone"));
    info.extend(message(12, &integer(1, 1)));
    let mut request = integer(1, now_ms);
    request.extend(message(2, &info));
    request.extend(integer(3, 256));
    if let Some(auth) = auth {
        request.extend(message(4, auth));
    }
    let mut physical = integer(1, u64::from(connection));
    physical.extend(integer(2, 1));
    physical.extend(message(3, &request));
    let body = message(2, &message(2, &physical));
    let mut out = vec![9, 4];
    out.extend(((body.len() + 4) as u16).to_be_bytes());
    out.extend(body);
    out
}
pub fn device_info(input: &[u8]) -> Option<Vec<Field<'_>>> {
    if input.len() < 4
        || input[0..2] != [9, 4]
        || usize::from(u16::from_be_bytes([input[2], input[3]])) != input.len()
    {
        return None;
    }
    let physical = bytes_field(bytes_field(&input[4..], 2)?, 2)?;
    if !fields(physical)?.contains(&Field::Integer(2, 2)) {
        return None;
    }
    fields(bytes_field(bytes_field(physical, 4)?, 2)?)
}
pub struct Segment<'a> {
    pub command: u8,
    pub fragment: u8,
    pub timestamp: u32,
    pub sequence: u32,
    pub body: &'a [u8],
}
fn little(input: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(input[p..p + 4].try_into().unwrap())
}
pub fn segments(input: &[u8]) -> Option<Vec<Segment<'_>>> {
    if input.is_empty() || input.len() > 65535 {
        return None;
    }
    let mut p = 0;
    let mut result = Vec::new();
    while p < input.len() {
        let h = input.get(p..p + 24)?;
        if little(h, 0) != 0x12345678 || !(81..=84).contains(&h[4]) {
            return None;
        }
        let length = usize::try_from(little(h, 20)).ok()?;
        let end = p.checked_add(24)?.checked_add(length)?;
        result.push(Segment {
            command: h[4],
            fragment: h[5],
            timestamp: little(h, 8),
            sequence: little(h, 12),
            body: input.get(p + 24..end)?,
        });
        p = end;
    }
    Some(result)
}
pub fn packet(command: u8, timestamp: u32, sequence: u32, next: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + body.len());
    out.extend(0x12345678_u32.to_le_bytes());
    out.extend([command, 0, 128, 0]);
    for value in [timestamp, sequence, next, body.len() as u32] {
        out.extend(value.to_le_bytes());
    }
    out.extend(body);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_overflow_and_truncation() {
        assert!(fields(&[8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2]).is_none());
        assert!(fields(&[0]).is_none());
        assert!(fields(&[10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1]).is_none());
        assert!(fields(&[10, 3, 1]).is_none());
    }
    #[test]
    fn segment_roundtrip_and_boundaries() {
        let a = packet(81, 123, 0, 0, b"test");
        let parsed = segments(&a).unwrap();
        assert_eq!(parsed[0].body, b"test");
        assert_eq!(parsed[0].timestamp, 123);
        for n in 0..a.len() {
            assert!(segments(&a[..n]).is_none());
        }
        let mut b = a.clone();
        b.extend(packet(82, 123, 0, 1, &[]));
        assert_eq!(segments(&b).unwrap().len(), 2);
    }
    #[test]
    fn bounded_random_input() {
        let mut seed = 0x4321_u32;
        for length in 0..2048 {
            let value: Vec<u8> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = fields(&value);
            let _ = segments(&value);
            let _ = device_info(&value);
        }
    }
}
