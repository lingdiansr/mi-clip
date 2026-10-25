//! Authenticated TCP file records. No bytes are published by this decoder.
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit},
};

pub(crate) const MAX_RECORD: usize = 2 * 1024 * 1024 + 4096;
pub(crate) struct Chunk {
    pub stream: u32,
    pub offset: u64,
    pub data: Vec<u8>,
}

pub(crate) struct Receiver {
    stream: u32,
    file: Option<crate::file_store::IncomingFile>,
    received: u64,
}
impl Receiver {
    pub fn new(
        stream: u32,
        directory: &std::path::Path,
        name: &str,
        size: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            stream,
            received: 0,
            file: Some(crate::file_store::IncomingFile::create(
                directory, name, size,
            )?),
        })
    }
    /// A true result means the authenticated end record was checked and the
    /// complete file was committed. Partial records never publish a filename.
    pub fn push(&mut self, chunk: Chunk) -> anyhow::Result<bool> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Data after completed file"))?;
        anyhow::ensure!(
            chunk.stream == self.stream && chunk.offset == file.received(),
            "File stream identity or offset mismatch"
        );
        let ended = chunk.data.is_empty();
        file.write(&chunk.data)?;
        self.received = file.received();
        if ended {
            self.file.take().unwrap().commit(None)?;
        }
        Ok(ended)
    }
    pub fn received(&self) -> u64 {
        self.received
    }
}

pub(crate) fn record_size(header: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(
        header.len() >= 10 && header[..6] == [0; 6],
        "Unsupported file TCP header"
    );
    let length = usize::try_from(u32::from_be_bytes(header[6..10].try_into()?))?;
    anyhow::ensure!(
        (28..=MAX_RECORD).contains(&length),
        "Invalid file TCP record size"
    );
    Ok(10 + length)
}

pub(crate) fn open(key: &[u8; 16], record: &[u8]) -> anyhow::Result<Chunk> {
    anyhow::ensure!(
        record_size(record)? == record.len(),
        "Incomplete file TCP record"
    );
    let encrypted = &record[10..];
    // Express stores nonce, tag, ciphertext. The AEAD API expects ciphertext,
    // tag; the metadata footer is inside the authenticated plaintext.
    let mut ciphertext = encrypted[28..].to_vec();
    ciphertext.extend(&encrypted[12..28]);
    let mut plain = Aes128Gcm::new_from_slice(key)
        .unwrap()
        .decrypt(Nonce::from_slice(&encrypted[..12]), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("File TCP authentication failed"))?;
    anyhow::ensure!(plain.len() >= 2, "Missing file stream footer");
    let footer_size = usize::from(u16::from_be_bytes(plain[plain.len() - 2..].try_into()?));
    anyhow::ensure!(
        (8..=4096).contains(&footer_size) && footer_size + 2 <= plain.len(),
        "Invalid file stream footer size"
    );
    let data_size = plain.len() - footer_size - 2;
    let footer = crate::file_transport::frame(&plain[data_size..plain.len() - 2])?;
    anyhow::ensure!(
        (footer.kind, footer.tag) == (0x100, 0x100),
        "Unsupported file stream footer"
    );
    let fields = crate::file_transport::nodes(footer.value)?;
    anyhow::ensure!(fields.len() == 4, "Invalid file stream footer fields");
    let get = |tag, kind| -> anyhow::Result<&[u8]> {
        let mut matches = fields.iter().filter(|f| f.tag == tag);
        let field = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing file stream footer field"))?;
        anyhow::ensure!(
            field.kind == kind && matches.next().is_none(),
            "Ambiguous file stream footer field"
        );
        Ok(field.value)
    };
    anyhow::ensure!(get(0, 5)?.is_empty(), "Unexpected inline file stream bytes");
    let stream = u32::from_be_bytes(get(1, 3)?.try_into()?);
    let offset = u64::from_be_bytes(get(2, 4)?.try_into()?);
    let length = usize::try_from(u32::from_be_bytes(get(3, 3)?.try_into()?))?;
    anyhow::ensure!(
        offset <= crate::file_store::MAX_FILE_SIZE
            && length == data_size
            && length <= 2 * 1024 * 1024,
        "File stream length or offset mismatch"
    );
    plain.truncate(data_size);
    Ok(Chunk {
        stream,
        offset,
        data: plain,
    })
}

/// Encode a bounded file record; Android must still acknowledge task completion.
pub(crate) fn seal(
    key: &[u8; 16],
    stream: u32,
    offset: u64,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use crate::file_transport::{tlv, union};
    anyhow::ensure!(
        data.len() <= 2 * 1024 * 1024,
        "Oversized outgoing file record"
    );
    let mut fields = tlv(5, 0, &[])?;
    fields.extend(tlv(3, 1, &stream.to_be_bytes())?);
    fields.extend(tlv(4, 2, &offset.to_be_bytes())?);
    fields.extend(tlv(3, 3, &(data.len() as u32).to_be_bytes())?);
    let footer = union(256, 256, &fields)?;
    let mut plain = data.to_vec();
    plain.extend(&footer);
    plain.extend((footer.len() as u16).to_be_bytes());
    let nonce = crate::private::random::<12>()?;
    let sealed = Aes128Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow::anyhow!("File encryption failed"))?;
    let mut record = vec![0; 6];
    record.extend(((sealed.len() + 12) as u32).to_be_bytes());
    record.extend(nonce);
    record.extend(&sealed[sealed.len() - 16..]);
    record.extend(&sealed[..sealed.len() - 16]);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(data: &[u8], offset: u64) -> Vec<u8> {
        use crate::file_transport::tlv;
        let mut fields = tlv(5, 0, &[]).unwrap();
        fields.extend(tlv(3, 1, &7u32.to_be_bytes()).unwrap());
        fields.extend(tlv(4, 2, &offset.to_be_bytes()).unwrap());
        fields.extend(tlv(3, 3, &(data.len() as u32).to_be_bytes()).unwrap());
        let mut union = 256u16.to_be_bytes().to_vec();
        union.extend(tlv(256, 256, &fields).unwrap());
        let footer = tlv(257, 65535, &union).unwrap();
        let mut plain = data.to_vec();
        plain.extend(&footer);
        plain.extend((footer.len() as u16).to_be_bytes());
        let nonce = [0x24; 12];
        let sealed = Aes128Gcm::new_from_slice(&[0x42; 16])
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
            .unwrap();
        let mut record = vec![0; 6];
        record.extend(((sealed.len() + 12) as u32).to_be_bytes());
        record.extend(nonce);
        record.extend(&sealed[sealed.len() - 16..]);
        record.extend(&sealed[..sealed.len() - 16]);
        record
    }
    #[test]
    fn receiver_requires_matching_identity_order_and_authenticated_end_before_publication() {
        let directory = std::env::temp_dir().join(format!(
            "clip-receiver-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let mut receiver = Receiver::new(7, &directory, "sample.bin", 4).unwrap();
        assert!(
            receiver
                .push(Chunk {
                    stream: 8,
                    offset: 0,
                    data: b"data".to_vec()
                })
                .is_err()
        );
        assert!(
            receiver
                .push(Chunk {
                    stream: 7,
                    offset: 1,
                    data: b"data".to_vec()
                })
                .is_err()
        );
        assert!(
            !receiver
                .push(Chunk {
                    stream: 7,
                    offset: 0,
                    data: b"data".to_vec()
                })
                .unwrap()
        );
        assert!(!directory.join("sample.bin").exists());
        assert!(
            receiver
                .push(Chunk {
                    stream: 7,
                    offset: 4,
                    data: Vec::new()
                })
                .unwrap()
        );
        assert_eq!(
            std::fs::read(directory.join("sample.bin")).unwrap(),
            b"data"
        );
        assert!(
            receiver
                .push(Chunk {
                    stream: 7,
                    offset: 4,
                    data: Vec::new()
                })
                .is_err()
        );
        let mut incomplete = Receiver::new(9, &directory, "partial.bin", 5).unwrap();
        incomplete
            .push(Chunk {
                stream: 9,
                offset: 0,
                data: b"x".to_vec(),
            })
            .unwrap();
        assert!(
            incomplete
                .push(Chunk {
                    stream: 9,
                    offset: 1,
                    data: Vec::new()
                })
                .is_err()
        );
        assert!(!directory.join("partial.bin").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn authenticated_stream_preserves_offset_and_rejects_tampering() {
        let input = record(b"synthetic file", 0);
        let chunk = open(&[0x42; 16], &input).unwrap();
        assert_eq!(
            (chunk.stream, chunk.offset, chunk.data.as_slice()),
            (7, 0, b"synthetic file".as_slice())
        );
        let end = open(&[0x42; 16], &record(&[], 14)).unwrap();
        assert!(end.data.is_empty());
        assert_eq!(end.offset, 14);
        assert!(open(&[0x43; 16], &input).is_err());
        for index in [0, 6, 9, 10, 22, input.len() - 1] {
            let mut bad = input.clone();
            bad[index] ^= 1;
            assert!(open(&[0x42; 16], &bad).is_err());
        }
        for end in 0..input.len() {
            assert!(open(&[0x42; 16], &input[..end]).is_err());
        }
    }
}
