//! File-channel control messages. File bytes never travel through this parser.
use crate::wire::{self, Field};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::ecdsa::{SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

fn bytes(input: &[u8], field: u32) -> anyhow::Result<&[u8]> {
    wire::bytes_field(input, field).ok_or_else(|| anyhow::anyhow!("Missing file-channel field"))
}
fn number(input: &[u8], field: u32) -> Option<u64> {
    wire::fields(input)?.into_iter().find_map(|f| match f {
        Field::Integer(n, v) if n == field => Some(v),
        _ => None,
    })
}

pub(crate) struct Incoming {
    pub peer_id: u8,
    pub nonce: u32,
}

pub(crate) fn sync_reply(
    key: &[u8; 32],
    signing: &SigningKey,
    uid: &str,
) -> anyhow::Result<Vec<u8>> {
    use crate::wire::{integer, message};
    let challenge = crate::private::random::<32>()?;
    let signature: Signature = signing.sign(&challenge);
    let mut proof = message(1, &challenge);
    proof.extend(message(2, signature.to_der().as_bytes()));
    let mut credential = integer(1, 2);
    credential.extend(message(3, &proof));
    let mut group = integer(1, 1);
    group.extend(message(3, &credential));
    let iv = crate::private::random::<12>()?;
    let mut encrypted = iv.to_vec();
    encrypted.extend(
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(&iv), group.as_slice())
            .map_err(|_| anyhow::anyhow!("File-channel proof encryption failed"))?,
    );
    let salt = crate::private::random::<8>()?;
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(Sha256::digest(uid.as_bytes()));
    let mut feature = message(1, &salt);
    feature.extend(message(2, &hash.finalize()));
    let mut sync = integer(1, 15000);
    sync.extend(integer(2, 48));
    // The initial client connection uses local key-context index 1.
    sync.extend(integer(3, 1));
    sync.extend(message(4, b"com.xiaomi.hyperConnect:miLyraShareTransfer"));
    sync.extend(message(5, &feature));
    sync.extend(message(6, &encrypted));
    let mut inner = integer(1, 5);
    inner.extend(message(6, &sync));
    Ok(inner)
}

pub(crate) struct Control<'a> {
    pub kind: u8,
    pub message_id: u16,
    pub body: &'a [u8],
}

/// The control channel has its own 16-byte header inside the encrypted envelope.
pub(crate) fn control(packet: &[u8]) -> anyhow::Result<Control<'_>> {
    anyhow::ensure!(
        (16..=u16::MAX as usize).contains(&packet.len()),
        "Invalid channel control length"
    );
    anyhow::ensure!(
        packet[0] == 0x10 && packet[1] == 0 && packet[3] == 16,
        "Unsupported channel control header"
    );
    anyhow::ensure!(
        u16::from_be_bytes([packet[4], packet[5]]) as usize == packet.len(),
        "Channel control length mismatch"
    );
    anyhow::ensure!(
        (1..=7).contains(&packet[2]),
        "Unsupported channel control type"
    );
    anyhow::ensure!(
        matches!(packet[6], 0 | 0x12) && packet[9..16].iter().all(|&b| b == 0),
        "Unsupported channel control options"
    );
    let message_id = u16::from_be_bytes([packet[7], packet[8]]);
    anyhow::ensure!(
        (packet[6] == 0) == (message_id == 0),
        "Invalid channel control message ID"
    );
    Ok(Control {
        kind: packet[2],
        message_id,
        body: &packet[16..],
    })
}

/// Reuse only the key and certificate established by the current live handshake.
pub(crate) fn incoming(
    logical: &[u8],
    key: &[u8; 32],
    peer: &VerifyingKey,
) -> anyhow::Result<Option<Incoming>> {
    if number(logical, 4).unwrap_or(0) != 0 {
        return Ok(None);
    }
    let Ok(inner) = bytes(logical, 5) else {
        return Ok(None);
    };
    if number(inner, 1) != Some(5) {
        return Ok(None);
    }
    let sync = bytes(inner, 6)?;
    if bytes(sync, 4)? != b"com.xiaomi.hyperConnect:miLyraShareTransfer" {
        return Ok(None);
    }
    anyhow::ensure!(logical.len() <= 4096, "Oversized file-channel request");
    anyhow::ensure!(
        number(logical, 2).unwrap_or(0) == 0,
        "Unexpected file-channel destination"
    );
    let peer_id = u8::try_from(number(logical, 1).unwrap_or(0))?;
    anyhow::ensure!(peer_id > 1, "Invalid file-channel source");
    let nonce =
        u32::try_from(number(logical, 3).ok_or_else(|| anyhow::anyhow!("Missing channel nonce"))?)?;
    let encrypted = bytes(sync, 6)?;
    anyhow::ensure!(
        (28..=2048).contains(&encrypted.len()),
        "Invalid file-channel credential size"
    );
    let clear = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("File-channel credential authentication failed"))?;
    anyhow::ensure!(
        number(&clear, 1) == Some(1),
        "Unsupported file-channel credential group"
    );
    let credential = bytes(&clear, 3)?;
    anyhow::ensure!(
        number(credential, 1) == Some(2),
        "Unsupported file-channel credential type"
    );
    let proof = bytes(credential, 3)?;
    let challenge = bytes(proof, 1)?;
    anyhow::ensure!(challenge.len() == 32, "Invalid file-channel challenge");
    peer.verify(challenge, &Signature::from_der(bytes(proof, 2)?)?)
        .map_err(|_| anyhow::anyhow!("File-channel peer signature failed"))?;
    Ok(Some(Incoming { peer_id, nonce }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{integer, message};
    use p256::ecdsa::{SigningKey, signature::Signer};
    #[test]
    fn control_header_rejects_truncation_length_mismatch_and_unknown_options() {
        let mut packet = vec![0x10, 0, 1, 16, 0, 18, 0x12, 1, 2, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        let frame = control(&packet).unwrap();
        assert_eq!(
            (frame.kind, frame.message_id, frame.body),
            (1, 258, &[8, 1][..])
        );
        for end in 0..packet.len() {
            assert!(control(&packet[..end]).is_err())
        }
        packet[6] = 0;
        assert!(control(&packet).is_err());
        packet[7..9].fill(0);
        assert!(control(&packet).is_ok());
        packet[9] = 1;
        assert!(control(&packet).is_err());
    }
    #[test]
    fn accepts_current_peer_and_rejects_wrong_key_signature_and_tampering() {
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let challenge = [9; 32];
        let signature: Signature = signing.sign(&challenge);
        let mut proof = message(1, &challenge);
        proof.extend(message(2, signature.to_der().as_bytes()));
        let mut credential = integer(1, 2);
        credential.extend(message(3, &proof));
        let mut group = integer(1, 1);
        group.extend(message(3, &credential));
        let key = [3; 32];
        let reply = sync_reply(&key, &signing, "1234").unwrap();
        let mut reply_logical = integer(1, 2);
        reply_logical.extend(integer(3, 123));
        reply_logical.extend(message(5, &reply));
        assert!(
            incoming(&reply_logical, &key, signing.verifying_key())
                .unwrap()
                .is_some()
        );
        let iv = [4; 12];
        let mut encrypted = iv.to_vec();
        encrypted.extend(
            Aes256Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt(Nonce::from_slice(&iv), group.as_slice())
                .unwrap(),
        );
        let mut sync = message(4, b"com.xiaomi.hyperConnect:miLyraShareTransfer");
        sync.extend(message(6, &encrypted));
        let mut inner = integer(1, 5);
        inner.extend(message(6, &sync));
        let mut logical = integer(1, 2);
        logical.extend(integer(3, 123));
        logical.extend(message(5, &inner));
        let request = incoming(&logical, &key, signing.verifying_key())
            .unwrap()
            .unwrap();
        assert_eq!((request.peer_id, request.nonce), (2, 123));
        assert!(incoming(&logical, &[5; 32], signing.verifying_key()).is_err());
        let wrong = SigningKey::from_slice(&[2; 32]).unwrap();
        assert!(incoming(&logical, &key, wrong.verifying_key()).is_err());
        let end = logical.len() - 1;
        logical[end] ^= 1;
        assert!(incoming(&logical, &key, signing.verifying_key()).is_err());
    }
}
