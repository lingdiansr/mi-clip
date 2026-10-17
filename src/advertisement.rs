//! Xiaomi DNS-SD AppData. Pure parsing, no logging of device identifiers.
#[derive(Debug, PartialEq, Eq)]
pub struct Advertisement<'a> {
    pub device_type: u8,
    pub device_id: [u8; 4],
    pub kcp_port: Option<u16>,
    pub model: Option<&'a str>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidAdvertisement {
    Header,
    Truncated,
    Extended,
    Connection,
    Name,
}
impl<'a> Advertisement<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, InvalidAdvertisement> {
        use InvalidAdvertisement::*;
        if !(7..=3072).contains(&bytes.len()) {
            return Err(Header);
        }
        let flags = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut result = Self {
            device_type: bytes[2],
            device_id: bytes[3..7].try_into().unwrap(),
            kcp_port: None,
            model: None,
        };
        let mut p = 7;
        for (bit, length) in [(1, 2), (2, 2), (4, 3)] {
            if flags & bit != 0 {
                p += length;
            }
        }
        if p > bytes.len() {
            return Err(Truncated);
        }
        while p < bytes.len() {
            let header = bytes.get(p..p + 2).ok_or(Truncated)?;
            let tag = header[0];
            let length = usize::from(header[1]);
            p += 2;
            let value = bytes.get(p..p + length).ok_or(Truncated)?;
            match tag {
                0 => {
                    let f = *value.first().ok_or(Extended)?;
                    let required = 1
                        + usize::from(f & 1 != 0)
                        + 2 * usize::from(f & 8 != 0)
                        + usize::from(f & 16 != 0);
                    if value.len() < required {
                        return Err(Extended);
                    }
                }
                10 => {
                    let f = *value.first().ok_or(Connection)?;
                    if f & 1 != 0 {
                        let port = value.get(1..3).ok_or(Connection)?;
                        result.kcp_port = Some(u16::from_be_bytes([port[0], port[1]]));
                    }
                }
                2 if flags & 8 == 0 => {
                    let name = std::str::from_utf8(value).map_err(|_| Name)?;
                    if name.contains('\0') {
                        return Err(Name);
                    }
                    result.model = Some(name);
                }
                _ => (),
            }
            p += length;
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_phone() {
        let value = [
            0, 0, 1, 1, 2, 3, 4, 10, 3, 1, 0x12, 0x34, 2, 4, b'T', b'e', b's', b't',
        ];
        let parsed = Advertisement::parse(&value).unwrap();
        assert_eq!(parsed.kcp_port, Some(0x1234));
        assert_eq!(parsed.model, Some("Test"));
        assert_eq!(parsed.device_id, [1, 2, 3, 4]);
        for end in 0..7 {
            assert!(Advertisement::parse(&value[..end]).is_err());
        }
        let mut encrypted = value;
        encrypted[1] = 8;
        assert_eq!(Advertisement::parse(&encrypted).unwrap().model, None);
    }
    #[test]
    fn hostile_lengths_and_names() {
        assert!(Advertisement::parse(&[0, 7, 1, 1, 2, 3, 4]).is_err());
        assert!(Advertisement::parse(&[0, 0, 1, 1, 2, 3, 4, 10, 2, 1, 3]).is_err());
        assert!(Advertisement::parse(&[0, 0, 1, 1, 2, 3, 4, 2, 1, 0xff]).is_err());
        assert!(Advertisement::parse(&[0, 0, 1, 1, 2, 3, 4, 2, 1, 0]).is_err());
    }
    #[test]
    fn bounded_random_inputs_never_panic() {
        let mut seed = 0x1234_u32;
        for length in 0..256 {
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = Advertisement::parse(&bytes);
        }
    }
}
